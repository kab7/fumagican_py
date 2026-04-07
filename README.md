# fumagican

`fumagican.py` extracts and flashes official Samsung NVMe firmware packages without booting Samsung's updater image and without manually running the bundled x86-only `fumagician`.

It was built around Samsung 990 Pro packages, but the overall flow is generic for Samsung updater ISOs that:

- keep the firmware files inside `initrd`
- use `fumagician` as the source of the AES key
- select the real inner image through Samsung `ReadBuffer`

## What It Does

Given a Samsung updater ISO, the script will:

1. open the ISO
2. extract and unpack `initrd`
3. locate `fumagician` and the outer firmware `.enc`
4. extract the AES-256 key from `fumagician`
5. decrypt the outer package into a ZIP bundle
6. read Samsung `ReadBuffer` from the SSD
7. choose the matching inner firmware image
8. decrypt the selected payload
9. flash it through raw `nvme admin-passthru`

It also supports:

- extract-only mode
- flashing an already extracted `.bin`
- reusing a saved `ReadBuffer` dump
- manual selector override
- manual slot override

## Why This Exists

For the tested Samsung 990 Pro case, plain:

```bash
nvme fw-download
nvme fw-commit
```

kept failing with:

```text
Invalid Firmware Image (0x107)
```

The working path was to mirror Samsung's updater more closely and use raw NVMe admin commands with:

- firmware download opcode `0x11`
- firmware commit opcode `0x10`
- `nsid = 0`
- transfer size `0x4000`

## Requirements

- Python 3
- `nvme-cli`
- either:
  - `pycryptodome`
  - `openssl`

No external ISO extraction tools are required for normal use. `fumagican.py` includes its own minimal ISO9660 reader and `cpio newc` parser.

## Quick Start

Full end-to-end flow from ISO:

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0
```

Safe verification run:

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --dry-run
```

`--dry-run` still reads `ReadBuffer`, selects the correct payload, decrypts it, and saves the resulting `.bin`, but it does not send the NVMe firmware download or commit commands.

## Usage

### Full Automatic Flow

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0
```

### Extract Only

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --output ./chosen.bin
```

### Flash An Existing Payload

```bash
python3 fumagican.py flash-existing \
  --device /dev/nvme0 \
  --payload ./chosen.bin
```

### Reuse A Saved ReadBuffer

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --readbuffer ./readbuffer.bin \
  --output ./chosen.bin
```

### Manual Selector Override

```bash
python3 fumagican.py extract \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --selector 3 \
  --output ./chosen.bin
```

### Manual Mode Without ISO

If you already extracted the updater files yourself:

```bash
python3 fumagican.py auto \
  --fumagician ./fumagician \
  --firmware ./8B2QJXD7.enc \
  --device /dev/nvme0
```

## Slot Handling

By default the script uses:

```text
--slot auto
```

That means:

1. try commit with slot `1`
2. if that path fails, re-download the payload and retry with slot `2`

You can force a slot explicitly:

```bash
python3 fumagican.py auto \
  --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso \
  --device /dev/nvme0 \
  --slot 2
```

For the investigated 990 Pro:

- slot `1` was the active slot
- slot `1` was reported as read/write
- the safest default was to try `1` first, then fall back to `2`

## Progress Output

Firmware download progress is shown as a compact single-line indicator instead of printing every individual `nvme admin-passthru` command:

```text
[*] download progress: ................................................................................................................................ 128/128
```

## How Image Selection Works

The script does not guess by capacity such as `1TB` or `2TB`.

Instead it follows Samsung's selector flow:

1. send Samsung vendor admin command `opcode 0x82`
2. parse the returned `ReadBuffer`
3. build a 4-byte hex string from bytes `0x20`, `0x21`, `0x24`, `0x25`
4. use the first nibble as the inner firmware selector

For example:

```text
30231109
```

selects the inner image with prefix:

```text
8B2QJXD7_3
```

## Slot Troubleshooting

If the flashing path behaves differently than expected, inspect the controller first:

```bash
nvme fw-log /dev/nvme0
nvme id-ctrl -H /dev/nvme0
```

Useful fields:

- `afi`: currently active firmware slot
- `frs1`, `frs2`, `frs3`: firmware revisions present in slots
- `frmw`: number of supported slots and whether slot 1 is writable

Recommended approach:

1. start with the default `--slot auto`
2. if needed, force `--slot 1`
3. if that fails, force `--slot 2`

## How The `.enc` File Is Stored In The ISO

The Samsung updater ISO does not keep the firmware package directly in the top-level ISO tree. The relevant files live inside `initrd`, which is a gzip-compressed `cpio` archive.

For the tested image, the relevant paths inside `initrd` were:

```text
root/fumagician/fumagician
root/fumagician/fumagician.sh
root/fumagician/8B2QJXD7.enc
root/fumagician/DSRD.enc
```

You normally do not need to extract these manually, because `fumagican.py --iso ...` already does it.

If you still want to inspect the ISO by hand, tools like `bsdtar` can be used for ad-hoc extraction, but they are not required by the script itself.

## Safety

This tool is intended for official Samsung firmware packages only.

It does not prove that every package is safe for every Samsung model or revision. It reproduces the selection and flashing path that matched the tested updater behavior.

Flashing SSD firmware is inherently risky. If the disk is already running the expected firmware version, prefer `--dry-run` over re-flashing just to test the tool.

## Tested Result

On the investigated Samsung 990 Pro case:

- selecting the correct inner image by `ReadBuffer` mattered
- plain `nvme fw-download/fw-commit` still failed with `0x107`
- raw `nvme admin-passthru` with Samsung-matched command layout succeeded
