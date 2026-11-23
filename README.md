# Apple AirPower (B431) Bootloader Dump Exploit

This is a bootloader dump exploit for the AirPower B431. It dumps Apple’s 32 KiB
product bootloader from the device’s internal flash.

## What you need

- macOS with `clang`, `pkg-config`, and Homebrew `libusb-1.0`
- A healthy AirPower B431 running its normal application firmware
- No bootloader reference file is needed. The runner verifies the recovered
  dump against the accepted expected SHA-256 below.

```text
ef09627e43ef6cfcd6346d3801d47b2ea96632c5f2ac44285444e54be739aa42
```

## Check the project before touching hardware

Run:

```bash
python3 dump_bootloader.py --self-test
python3 dump_bootloader.py --dry-run
```

You should see:

```text
self-test: PASS
```

The dry run checks the exploit artifact and prints the expected bootloader
size and SHA-256.

## Run the dump

Connect the AirPower by USB, then run:

```bash
python3 dump_bootloader.py
```

After the exploit prints the bootloader, the runner will ask you to
power-cycle the AirPower. Wait for it to restart, then press Enter.

## Which bootloader is dumped?

This exploit dumps **Apple’s B431 bootloader**, stored in the first 32 KiB of
the MCU’s internal flash:

```text
0x08000000..0x08007fff
```

It does **not** dump the CPU vendor’s bootloader. In particular, it does not
dump the silicon vendor’s mask-ROM loader, system bootloader, or built-in DFU
bootloader. Those execute before or independently of the Apple image and are
not the 32 KiB flash region read by this exploit.

It also does not dump the MCU application or the FPGA image.

## How the exploit and dump work

The AirPower normally starts a USB serial console. The exploit uses that
console and the device’s DFU interface.

These are the main steps:

1. The runner opens the AirPower console at 1,250,000 baud.
2. It checks that the FPGA still has the expected factory version, `7.3.2.0`.
3. It saves the original manifest. The manifest tells the firmware where an
   update image lives.
4. It writes an 8,416-byte crafted VME image into external flash at `0x90400000`.
5. It temporarily changes manifest slot 3 so `fpga flash` will read that crafted image.
6. It sends `fpga flash` exactly once.
7. The crafted image arranges the VME heap so a fake memory block overlaps a saved return address.
8. When the parser returns, it jumps to a small Thumb handler that was staged in RAM.
9. That handler reads Apple’s bootloader region, `0x08000000..0x08007fff`.
10. It prints Apple’s 32,768 bootloader bytes as 1,024 hexadecimal lines between
    `B431 BOOT BEGIN` and `B431 BOOT END`.
11. The runner decodes those lines and checks their size, framing, line count,
    and SHA-256.
12. The final handler parks after it finishes, so the runner asks you to power-cycle the AirPower.
13. After the reboot, the runner restores the manifest, erases staging, and
    checks the FPGA version again.

The key idea is the return pivot. The crafted VME image changes a saved
return address in the heap. When the parser returns normally, it jumps to the
handler instead.

## Where the files are written

Each run gets its own directory:

```text
runs/<run-directory>/
├── bootloader-08000000-08007fff.bin
└── artifacts/
    ├── state.json
    ├── events.jsonl
    ├── rx.bin
    ├── result.json
    ├── console-responses/
    └── dfu/
```

Apple’s recovered bootloader is kept at the top level so it is easy to find. Every other
generated file is placed under `artifacts/`.

The runner prints the bootloader path only when that file is written. Other
paths are not printed, but they are recorded in `artifacts/events.jsonl`.

Find the newest run with:

```bash
RUN=$(ls -dt runs/* | head -1)
```

Check the result with:

```bash
cat "$RUN/artifacts/result.json"
```

## If a run stops

Do not start a fresh run after `fpga flash` has been sent.

Power-cycle the AirPower, then resume the same run directory:

```bash
python3 dump_bootloader.py --resume runs/<run-directory>
```

The runner remembers that the exploit was triggered. It finishes cleanup
instead of sending `fpga flash` again.

## Exploit artifact

The exploit input is:

```text
payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```

The runner pads this artifact to three erased 4 KiB flash sectors before
staging it. It does not fetch or regenerate the exploit during a run.
