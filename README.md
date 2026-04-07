# fumagican

`fumagican.py` is a single-file helper for extracting and flashing official Samsung NVMe firmware packages without booting Samsung's updater image or running the bundled x86-only `fumagician` by hand.

The intended workflow is simple:

1. point the script at a Samsung updater ISO
2. point it at the target NVMe controller
3. let it do the rest

It was built around Samsung 990 Pro firmware packages and reproduces the Samsung-specific path that actually worked in testing.

## What it does

Given a Samsung updater ISO, the script will:

1. open the ISO
2. extract `initrd`
3. unpack `initrd` and locate:
   - `fumagician`
   - the outer firmware `.enc`
4. extract the AES-256 key from `fumagician`
5. decrypt the outer package into a ZIP bundle
6. read Samsung `ReadBuffer` from the target SSD
7. select the correct inner firmware image for that SSD
8. decrypt the selected inner payload
9. flash it with raw `nvme admin-passthru`

It also supports:

- extracting the selected payload without flashing
- flashing an already extracted `.bin`
- working from already extracted `fumagician` + outer `.enc`
- saving or reusing a `ReadBuffer` dump
- manual selector override when needed

## Why this exists

For the tested Samsung 990 Pro case, plain:

```bash
nvme fw-download
nvme fw-commit
```

kept failing with:

```text
Invalid Firmware Image (0x107)
```

The working path was to mirror Samsung's own updater more closely and send firmware through raw `nvme admin-passthru` with:

- firmware download opcode `0x11`
- firmware commit opcode `0x10`
- `nsid = 0`
- transfer size `0x4000`
- commit slot selection controlled by `--slot`

## Requirements

- Python 3
- `nvme-cli`
- either:
  - `pycryptodome`, or
  - `openssl`

The script does not require `bsdtar`, `7z`, or other archive tools for ISO mode. It includes its own minimal ISO9660 reader and `cpio newc` parser.

## Quick start

Full end-to-end flow from ISO:

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0
```

This is the main mode. It:

- opens the ISO
- extracts the bundled updater files
- reads `ReadBuffer` from the SSD
- picks the right inner image
- decrypts it
- flashes it

## Usage

### Full automatic flow

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0
```

### Extract only

Decrypts the package and writes only the selected payload.

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --output ./chosen.bin
```

### Dry run

Runs the full selection and extraction flow, but does not actually send NVMe firmware download or commit commands.

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --dry-run
```

In `auto --dry-run` mode the script still:

- opens the ISO
- extracts the bundled files
- reads `ReadBuffer`
- selects the matching inner firmware
- decrypts and saves the selected payload

but it does not actually send firmware download or commit commands to the SSD.

If `--output` is not specified, the payload is saved as `<inner>.bin` in the current directory.

### Save `ReadBuffer` while extracting

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --save-readbuffer ./readbuffer.bin \
  --output ./chosen.bin
```

### Reuse a previously saved `ReadBuffer`

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --readbuffer ./readbuffer.bin \
  --output ./chosen.bin
```

### Manual selector override

If you already know the Samsung selector nibble:

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --selector 3 \
  --output ./chosen.bin
```

### Flash an already extracted payload

```bash
python3 fumagican.py flash-existing \
  --device /dev/nvme0 \
  --payload ./chosen.bin
```

By default the script uses `--slot auto`, which tries slot `1` first and then retries with slot `2` if slot `1` fails.

If you want to force a specific slot:

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --slot 2
```

### Manual mode without ISO

If you already extracted the updater files from the ISO, you can still work directly from them:

```bash
python3 fumagican.py auto \
  --fumagician ./fumagician \
  --firmware ./8B2QJXD7.enc \
  --device /dev/nvme0
```

## Logged steps

The script logs the major steps in plain language, for example:

- opened ISO
- extracted `initrd`
- located `fumagician`
- located outer firmware package
- extracted AES key
- decrypted outer ZIP bundle
- read and parsed `ReadBuffer`
- selected the matching inner firmware
- decrypted payload
- started firmware download
- committed firmware
- retried with another slot when `--slot auto` is used

## How image selection works

The script does not guess based on capacity such as `1TB` or `2TB`.

Instead it follows Samsung's selector flow:

1. send Samsung vendor admin command `opcode 0x82`
2. parse the returned `ReadBuffer`
3. build a 4-byte hex string from bytes `0x20`, `0x21`, `0x24`, `0x25`
4. use the first nibble as the inner firmware selector

For example, a parsed `ReadBuffer` of:

```text
30231109
```

selects the inner firmware variant with prefix:

```text
8B2QJXD7_3
```

## How the `.enc` file is extracted from ISO

The Samsung updater ISO does not keep the firmware files directly in the top-level ISO tree. They live inside `initrd`, which is a gzip-compressed cpio archive.

Manual extraction looks like this:

```bash
bsdtar -xOf Samsung_SSD_990_PRO_8B2QJXD7.iso initrd > initrd.gz
python3 - <<'PY'
from pathlib import Path
import gzip
Path("initrd.cpio").write_bytes(gzip.decompress(Path("initrd.gz").read_bytes()))
PY
bsdtar -tf initrd.cpio | rg 'root/fumagician'
bsdtar -xOf initrd.cpio root/fumagician/fumagician > fumagician
bsdtar -xOf initrd.cpio root/fumagician/8B2QJXD7.enc > 8B2QJXD7.enc
```

For the tested image, the relevant files inside `initrd.cpio` were:

```text
root/fumagician/fumagician
root/fumagician/fumagician.sh
root/fumagician/8B2QJXD7.enc
root/fumagician/DSRD.enc
```

You normally do not need to do this manually, because `fumagican.py --iso ...` already performs the extraction automatically.

## Safety

This script is intended for official Samsung firmware packages only.

It does not prove that every package is safe for every Samsung model or revision. It reproduces the selection and flashing path that matched the tested Samsung updater behavior.

Flashing SSD firmware is inherently risky. If you do not understand the package you are sending to the controller, do not run the flashing step.

## Slot troubleshooting

If flashing behaves differently than expected, inspect the controller firmware slot state:

```bash
nvme fw-log /dev/nvme0
nvme id-ctrl -H /dev/nvme0
```

Useful fields:

- `afi`: currently active firmware slot
- `frs1`, `frs2`, `frs3`: firmware revisions stored in slots
- `frmw`: number of supported slots and whether slot 1 is read-only or read/write

Recommended approach:

- start with the default `--slot auto`
- if needed, force a specific slot with `--slot 1` or `--slot 2`
- if slot 1 is active and writable, forcing slot 1 may be the closest match to the original Samsung updater behavior
- if slot 1 behaves badly on your controller, try slot 2 explicitly

## Tested result

On the investigated Samsung 990 Pro case:

- selecting the correct inner image by `ReadBuffer` mattered
- `nvme fw-download/fw-commit` still failed with `0x107`
- raw `nvme admin-passthru` with Samsung-matched command layout succeeded
