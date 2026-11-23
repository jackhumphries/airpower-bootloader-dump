# B431 Apple Bootloader Dump Exploit Payload

This directory contains the immutable input for the Apple bootloader dump
exploit:

```text
airpower-return-pivot-boot-dump.apple-wrapped.bin
```

The file is:

- size: 8,416 bytes (`0x20e0`);
- SHA-256: `1b8f34f05d024b8124d6065f903511ad07fb3cd2a7ce3b210a9323c1df8be071`;
- format: an Apple-wrapped VME image;
- not an ELF, Mach-O image, firmware image, or copy of the bootloader.

The Python runner stages this file in external flash and points firmware-update
slot 3 at it. Apple’s bootloader bytes are read from the AirPower at runtime;
they are not stored in this artifact.

## File layout

| File range | Size | Contents |
|---|---:|---|
| `0x0000..0x001f` | 32 bytes | Apple/FPGA wrapper header copied from a legitimate factory image |
| `0x0020..0x0029` | 10 bytes | VME header bytes copied from the factory image |
| `0x002a..0x00af` | 134 bytes | CRC tuning and VME heap-grooming records |
| `0x00b0..0x020a7` | 8,184 bytes | Oversized `MASKORCL` row used as the heap-overflow payload |
| `0x020a8..0x020df` | 56 bytes | Final VME allocation and reallocation trigger records |

Most of the 8,184-byte overflow row is zero filler. The zeros preserve the exact
heap and SRAM offsets needed by the exploit.

## Wrapper and VME prefix

The file starts with the Apple wrapper magic:

```text
ApPlEiNc
```

This makes the crafted stream resemble the FPGA update format accepted by the
B431 firmware. It is not encryption and does not hide the remaining bytes.

A VME comment near offset `0x002e` contains:

```text
B431 heap oracle v13 force
```

At offset `0x004a`, these eight bytes tune the VME CRC:

```text
e7 d8 00 00 00 00 00 00
```

They make the allocator derive a fake chunk size of `0x06b9`.

The following VME records allocate, free, and resize buffers so the later
oversized `MASK` row reaches the exploit’s expected heap layout.

## Oversized `MASKORCL` row

The overflow row starts at file offset `0x00b0` with the marker:

```text
MASKORCL
```

Its length is 8,184 bytes (`0x1ff8`).

### Fake allocator header

At file offset `0x0178`, the row contains these little-endian words:

```text
8c 28 02 20    -> 0x2002288c, the free-list sentinel
0f a9 ff 1f    -> 0x1fffa90f, the wrapped fake-chunk size
```

This fake header is staged at SRAM address:

```text
0x2003d2e0
```

The wrapped size makes allocator arithmetic wrap around to:

```text
0x2000fb60
```

That address is the saved return slot used by the VME row writer.

### Embedded Thumb handler

At file offset `0x01b0`, the overflow contains 278 bytes of little-endian Thumb
machine code. In the staged heap layout it starts at:

```text
0x2003d318
```

Its Thumb entry value is:

```text
0x2003d319
```

The low bit selects Thumb state.

The handler has no C runtime, literal pool, or separate linker output. It is
raw machine code embedded inside the VME row.

It performs the dump in this order:

1. Saves the registers it uses.
2. Calls the firmware output function at `0x0805a155` to print
   `B431 BOOT BEGIN`.
3. Sets its read pointer to Apple’s bootloader at internal-flash address
   `0x08000000`.
4. Reads exactly `0x8000` bytes, covering `0x08000000..0x08007fff`.
5. Converts each byte to two uppercase hexadecimal characters.
6. Prints 32 data bytes per line, producing 64 hexadecimal characters per line.
7. Calls the USB flush function at `0x08044be7` after every line.
8. Prints `B431 BOOT END` after all 1,024 lines.
9. Flushes the final output.
10. Enables interrupts with `cpsie i`.
11. Executes `dsb sy` and `isb sy`.
12. Waits in a bounded 32M-iteration loop so USB output can drain.
13. Writes proof word `0x48415242` to `0x20048010`.
14. Branches to itself until the AirPower is power-cycled.

The final self-loop is why the host runner asks for a power cycle after
the dump.

### Linked fake-header pointer

At file offset `0x20a0`, the overflow ends with:

```text
e0 d2 03 20    -> 0x2003d2e0
00 00 00 00
```

This links the allocator’s fake chunk to the fake header described above.

## Final trigger records

Near the end of the file is the VME comment:

```text
B431 VECTOR ENTRY PRE
```

The final control row starts at file offset `0x20c4`. Its four-byte control
value at `0x20c8` is:

```text
19 d3 03 20
```

This is little-endian for:

```text
0x2003d319
```

the staged Thumb handler entry.

The heap layout causes the VME row writer to write those four bytes into the
saved return slot at `0x2000fb60`. When the row writer returns normally, the
processor branches to the handler. This is the return pivot.

The remaining VME allocation requests force the wrapped TDO reallocation that
completes the pivot.

## Useful inspection commands

Verify the pinned artifact:

```bash
shasum -a 256 payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```

Show readable labels:

```bash
strings -a -t x payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```

Inspect exact bytes:

```bash
xxd -g1 payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```

Inspect the beginning of the oversized row:

```bash
xxd -g1 -s 0x00b0 -l 0x100 payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```

Inspect the final trigger records:

```bash
xxd -g1 -s 0x20a0 payload/airpower-return-pivot-boot-dump.apple-wrapped.bin
```
