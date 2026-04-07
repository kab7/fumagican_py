#!/usr/bin/env python3
"""Samsung NVMe firmware helper."""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn


MAGIC = b"_icianMAG_@*!.8&"
READBUFFER_OPCODE = "0x82"
READBUFFER_CDW10 = "0xfe000100"
READBUFFER_CDW11 = "0x1000"
READBUFFER_SIZE = 4096
FW_DOWNLOAD_OPCODE = "0x11"
FW_COMMIT_OPCODE = "0x10"
DEFAULT_XFER = 0x4000
ISO_INITRD_NAME = "initrd"
ISO_SECTOR_SIZE = 2048
DESCRIPTION = "Extract and flash official Samsung NVMe firmware packages."
EPILOG = """Examples:
  python3 fumagican.py auto --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso --device /dev/nvme0
  python3 fumagican.py auto --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso --device /dev/nvme0 --dry-run
  python3 fumagican.py extract --iso ./Samsung_SSD_990_PRO_8B2QJXD7.iso --device /dev/nvme0 --output ./chosen.bin
  python3 fumagican.py flash-existing --device /dev/nvme0 --payload ./chosen.bin
"""

AUTO_DESCRIPTION = (
    "Open a Samsung updater ISO or extracted firmware files, select the matching "
    "inner payload for the target SSD, and flash it."
)
EXTRACT_DESCRIPTION = (
    "Open a Samsung updater ISO or extracted firmware files, select the matching "
    "inner payload, and save it without flashing."
)
FLASH_DESCRIPTION = "Flash an already extracted Samsung firmware payload."


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


class FlashError(Exception):
    pass


@dataclass
class ResolvedSource:
    fumagician: Path
    firmware: Path
    source: str
    tempdir: tempfile.TemporaryDirectory[str] | None = None

    def cleanup(self) -> None:
        if self.tempdir is not None:
            self.tempdir.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fumagican.py",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=HelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True, title="commands")

    auto = subparsers.add_parser(
        "auto",
        help="extract, select, and flash",
        description=AUTO_DESCRIPTION,
        formatter_class=HelpFormatter,
    )
    add_flow_args(auto)
    add_flash_args(auto)
    auto.add_argument(
        "--output",
        type=Path,
        help="Optionally save the selected payload before flashing",
    )

    extract = subparsers.add_parser(
        "extract",
        help="extract and save selected payload",
        description=EXTRACT_DESCRIPTION,
        formatter_class=HelpFormatter,
    )
    add_flow_args(extract)
    extract.add_argument(
        "--output",
        type=Path,
        help="Where to save the selected payload; default is <inner>.bin in cwd",
    )

    flash = subparsers.add_parser(
        "flash-existing",
        help="flash an already extracted payload",
        description=FLASH_DESCRIPTION,
        formatter_class=HelpFormatter,
    )
    flash.add_argument("--device", required=True, help="NVMe controller, e.g. /dev/nvme0")
    flash.add_argument("--payload", required=True, type=Path, help="Existing decrypted .bin payload")
    add_flash_args(flash)

    return parser.parse_args()


def add_flow_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_argument_group("firmware source")
    source.add_argument("--iso", type=Path, help="Samsung bootable ISO image")
    source.add_argument("--fumagician", type=Path, help="Path to extracted Samsung fumagician binary")
    source.add_argument("--firmware", type=Path, help="Path to extracted outer Samsung .enc file")

    selection = parser.add_argument_group("device selection")
    selection.add_argument("--device", help="NVMe controller, e.g. /dev/nvme0")
    selection.add_argument("--readbuffer", type=Path, help="Existing 4096-byte ReadBuffer dump")
    selection.add_argument("--selector", help="Manual selector override, e.g. 3")
    selection.add_argument(
        "--save-readbuffer",
        type=Path,
        help="Save freshly read ReadBuffer dump to this path",
    )


def add_flash_args(parser: argparse.ArgumentParser) -> None:
    flash = parser.add_argument_group("flash options")
    flash.add_argument(
        "--xfer",
        type=int,
        default=DEFAULT_XFER,
        help=f"Chunk size for firmware download (default: {DEFAULT_XFER})",
    )
    flash.add_argument(
        "--slot",
        default="auto",
        metavar="SLOT",
        help="Commit slot: 1, 2, or auto (default: auto)",
    )
    flash.add_argument("--action", type=int, default=1, help="Firmware commit action (default: 1)")
    flash.add_argument("--dry-run", action="store_true", help="Simulate flashing without sending NVMe firmware commands")


def fail(message: str) -> NoReturn:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def log(message: str) -> None:
    print(f"[*] {message}")


def parse_slot_value(value: str) -> str | int:
    lowered = value.strip().lower()
    if lowered == "auto":
        return "auto"
    try:
        slot = int(lowered, 10)
    except ValueError:
        fail(f"invalid --slot value {value!r}; expected auto, 1, or 2")
    if slot <= 0:
        fail("--slot must be a positive integer or 'auto'")
    return slot


def resolve_slot_candidates(raw_slot: str) -> list[int]:
    parsed = parse_slot_value(raw_slot)
    if parsed == "auto":
        return [1, 2]
    return [parsed]


def run(cmd: list[str], *, input_data: bytes | None = None, dry_run: bool = False) -> subprocess.CompletedProcess[bytes]:
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    return subprocess.run(
        cmd,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def verify_magic(decrypted: bytes) -> bool:
    return decrypted[:16] == MAGIC


def unique_zip_entries(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    seen: set[str] = set()
    entries: list[zipfile.ZipInfo] = []
    for info in zf.infolist():
        if not info.filename.endswith(".enc"):
            continue
        name = Path(info.filename).name
        if name in seen:
            continue
        seen.add(name)
        entries.append(info)
    return entries


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        fail(f"required tool not found in PATH: {name}")
    return path


def decrypt_aes256_ecb(data: bytes, key: bytes) -> bytes:
    if len(data) % 16 != 0:
        fail(f"encrypted data length must be multiple of 16, got {len(data)}")

    try:
        from Crypto.Cipher import AES  # type: ignore
    except ImportError:
        openssl = require_tool("openssl")
        key_hex = key.hex()
        try:
            proc = run(
                [openssl, "enc", "-aes-256-ecb", "-d", "-nopad", "-K", key_hex],
                input_data=data,
            )
        except subprocess.CalledProcessError as exc:
            fail(exc.stderr.decode("utf-8", "ignore").strip() or "openssl decryption failed")
        return proc.stdout

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def candidate_keys(fumagician: Path) -> list[bytes]:
    data = fumagician.read_bytes()
    matches = re.findall(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{43}=)(?![A-Za-z0-9+/])", data)
    keys: list[bytes] = []
    seen: set[bytes] = set()

    for match in matches:
        try:
            key = base64.b64decode(match, validate=True)
        except Exception:
            continue
        if len(key) != 32 or key in seen:
            continue
        seen.add(key)
        keys.append(key)

    if not keys:
        fail(f"no 32-byte base64 AES keys found in {fumagician}")
    return keys


def extract_key(fumagician: Path, encrypted_firmware: Path) -> bytes:
    header = encrypted_firmware.read_bytes()[:32]
    for key in candidate_keys(fumagician):
        decrypted = decrypt_aes256_ecb(header, key)
        if verify_magic(decrypted):
            return key
    fail("could not verify any key candidate against firmware header")


def normalize_iso_name(name: str) -> str:
    return name.split(";", 1)[0].rstrip(".").lower()


def parse_iso_dir_record(record: bytes) -> dict[str, object]:
    if not record:
        fail("empty ISO directory record")

    extent = int.from_bytes(record[2:6], "little")
    size = int.from_bytes(record[10:14], "little")
    flags = record[25]
    name_len = record[32]
    raw_name = record[33 : 33 + name_len]

    if raw_name == b"\x00":
        name = "."
    elif raw_name == b"\x01":
        name = ".."
    else:
        name = raw_name.decode("ascii", "ignore")

    return {
        "name": name,
        "extent": extent,
        "size": size,
        "is_dir": bool(flags & 0x02),
    }


def iter_iso_dir_entries(iso_data: bytes, extent: int, size: int) -> list[dict[str, object]]:
    start = extent * ISO_SECTOR_SIZE
    end = start + size
    if end > len(iso_data):
        fail("ISO directory extent exceeds file size")

    entries: list[dict[str, object]] = []
    offset = start

    while offset < end:
        record_len = iso_data[offset]
        if record_len == 0:
            next_sector = ((offset // ISO_SECTOR_SIZE) + 1) * ISO_SECTOR_SIZE
            if next_sector <= offset:
                break
            offset = next_sector
            continue

        record = iso_data[offset : offset + record_len]
        entry = parse_iso_dir_record(record)
        if entry["name"] not in (".", ".."):
            entries.append(entry)
        offset += record_len

    return entries


def get_iso_root_record(iso_data: bytes) -> dict[str, object]:
    for sector in range(16, 64):
        start = sector * ISO_SECTOR_SIZE
        pvd = iso_data[start : start + ISO_SECTOR_SIZE]
        if len(pvd) < ISO_SECTOR_SIZE:
            break
        desc_type = pvd[0]
        ident = pvd[1:6]
        if ident != b"CD001":
            continue
        if desc_type == 1:
            root_len = pvd[156]
            return parse_iso_dir_record(pvd[156 : 156 + root_len])
        if desc_type == 255:
            break
    fail("could not locate ISO9660 primary volume descriptor")


def extract_iso_member(iso_path: Path, member: str) -> bytes:
    iso_data = iso_path.read_bytes()
    root = get_iso_root_record(iso_data)
    current = root

    for part in [chunk for chunk in member.split("/") if chunk and chunk != "."]:
        entries = iter_iso_dir_entries(
            iso_data,
            int(current["extent"]),
            int(current["size"]),
        )
        wanted = normalize_iso_name(part)
        match = next((entry for entry in entries if normalize_iso_name(str(entry["name"])) == wanted), None)
        if match is None:
            fail(f"could not find {member!r} inside ISO")
        current = match

    start = int(current["extent"]) * ISO_SECTOR_SIZE
    end = start + int(current["size"])
    if end > len(iso_data):
        fail(f"ISO member {member!r} exceeds file size")
    return iso_data[start:end]


def iter_cpio_entries(data: bytes) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    offset = 0

    while offset + 110 <= len(data):
        header = data[offset : offset + 110]
        magic = header[:6]
        if magic != b"070701":
            fail("unsupported initrd format: expected cpio newc")

        try:
            filesize = int(header[54:62], 16)
            namesize = int(header[94:102], 16)
        except ValueError:
            fail("invalid cpio header")

        name_start = offset + 110
        name_end = name_start + namesize
        if name_end > len(data):
            fail("cpio name exceeds archive size")

        raw_name = data[name_start:name_end]
        name = raw_name[:-1].decode("utf-8", "ignore") if raw_name.endswith(b"\x00") else raw_name.decode("utf-8", "ignore")
        data_start = (name_end + 3) & ~3
        data_end = data_start + filesize
        if data_end > len(data):
            fail(f"cpio member {name!r} exceeds archive size")

        if name == "TRAILER!!!":
            break

        entries.append((name, data[data_start:data_end]))
        offset = (data_end + 3) & ~3

    if not entries:
        fail("no files found in initrd cpio archive")
    return entries


def extract_from_iso(iso_path: Path) -> ResolvedSource:
    if not iso_path.exists():
        fail(f"ISO not found: {iso_path}")

    log(f"opened ISO: {iso_path}")
    initrd_gzip = extract_iso_member(iso_path, ISO_INITRD_NAME)
    log(f"extracted initrd: {len(initrd_gzip):,} bytes")
    try:
        initrd_cpio = gzip.decompress(initrd_gzip)
    except gzip.BadGzipFile:
        fail("ISO initrd is not a gzip-compressed cpio archive")
    log(f"unpacked initrd: {len(initrd_cpio):,} bytes")

    tempdir = tempfile.TemporaryDirectory(prefix="fumagican-iso-")
    temp_root = Path(tempdir.name)
    cpio_entries = iter_cpio_entries(initrd_cpio)
    cpio_map = {name: payload for name, payload in cpio_entries}

    fumagician_member = next((name for name in cpio_map if name.endswith("/fumagician/fumagician")), None)
    if not fumagician_member:
        tempdir.cleanup()
        fail("could not locate fumagician inside initrd")

    enc_members = [name for name in cpio_map if name.endswith(".enc") and "/fumagician/" in name]
    outer_candidates = [name for name in enc_members if Path(name).name.upper() != "DSRD.ENC"]
    if not outer_candidates:
        tempdir.cleanup()
        fail("could not locate outer firmware .enc inside initrd")

    if len(outer_candidates) == 1:
        firmware_member = outer_candidates[0]
    else:
        firmware_member = max(outer_candidates, key=lambda name: len(cpio_map[name]))

    log(f"located fumagician: {fumagician_member}")
    log(f"located outer firmware package: {firmware_member}")

    fumagician_path = temp_root / Path(fumagician_member).name
    firmware_path = temp_root / Path(firmware_member).name
    fumagician_path.write_bytes(cpio_map[fumagician_member])
    firmware_path.write_bytes(cpio_map[firmware_member])

    log(f"extracted bundled files to temporary workspace: {temp_root}")
    return ResolvedSource(
        fumagician=fumagician_path,
        firmware=firmware_path,
        source=f"ISO {iso_path}",
        tempdir=tempdir,
    )


def resolve_source(args: argparse.Namespace) -> ResolvedSource:
    if args.iso:
        if args.fumagician or args.firmware:
            fail("use either --iso or the pair --fumagician/--firmware")
        return extract_from_iso(args.iso)

    if not args.fumagician or not args.firmware:
        fail("need either --iso, or both --fumagician and --firmware")
    if not args.fumagician.exists():
        fail(f"fumagician not found: {args.fumagician}")
    if not args.firmware.exists():
        fail(f"firmware not found: {args.firmware}")

    log(f"using local fumagician: {args.fumagician}")
    log(f"using local outer firmware package: {args.firmware}")
    return ResolvedSource(
        fumagician=args.fumagician,
        firmware=args.firmware,
        source="local files",
    )


def decrypt_outer_zip(key: bytes, firmware: Path) -> bytes:
    decrypted = decrypt_aes256_ecb(firmware.read_bytes(), key)
    if not verify_magic(decrypted):
        fail("outer firmware header magic mismatch")
    zip_data = decrypted[32:]
    if zip_data[:4] != b"PK\x03\x04":
        fail("decrypted outer payload is not a ZIP archive")
    return zip_data


def parse_selector_from_rbuf(data: bytes) -> tuple[str, str]:
    if len(data) < 0x26:
        fail("ReadBuffer dump is too short")
    rbuf = "".join(f"{data[index]:02x}" for index in (0x20, 0x21, 0x24, 0x25))
    selector = rbuf[0]
    return rbuf, selector


def read_readbuffer(device: str) -> bytes:
    try:
        proc = run(
            [
                "nvme",
                "admin-passthru",
                device,
                f"--opcode={READBUFFER_OPCODE}",
                "--namespace-id=0",
                f"--cdw10={READBUFFER_CDW10}",
                f"--cdw11={READBUFFER_CDW11}",
                f"--data-len={READBUFFER_SIZE}",
                "--read",
                "--raw-binary",
            ]
        )
    except subprocess.CalledProcessError as exc:
        fail(exc.stderr.decode("utf-8", "ignore").strip() or "failed to read ReadBuffer")
    return proc.stdout


def resolve_selector(args: argparse.Namespace) -> tuple[str | None, str, str]:
    if args.selector:
        selector = args.selector[0]
        return None, selector, f"manual selector {selector}"

    if args.readbuffer:
        if not args.readbuffer.exists():
            fail(f"ReadBuffer dump not found: {args.readbuffer}")
        data = args.readbuffer.read_bytes()
        rbuf, selector = parse_selector_from_rbuf(data)
        return rbuf, selector, f"ReadBuffer file {args.readbuffer}"

    if not args.device:
        fail("need one of --selector, --readbuffer, or --device")

    data = read_readbuffer(args.device)
    if args.save_readbuffer:
        args.save_readbuffer.write_bytes(data)
    rbuf, selector = parse_selector_from_rbuf(data)
    return rbuf, selector, f"device {args.device}"


def inspect_outer_zip(zip_data: bytes) -> tuple[list[str], int]:
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
        entries = unique_zip_entries(zf)
        names = [Path(info.filename).name for info in entries]
        return names, len(zf.infolist())


def select_inner_entry(zip_data: bytes, outer_name: str, selector: str) -> tuple[str, bytes]:
    prefix = f"{outer_name}_{selector}"
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
        entries = unique_zip_entries(zf)
        for info in entries:
            inner_name = Path(info.filename).name
            if inner_name.startswith(prefix):
                return inner_name, zf.read(info)

    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
        available = [Path(info.filename).name for info in unique_zip_entries(zf)]
    fail(f"no inner firmware matched selector {selector!r}; available: {', '.join(available)}")


def decrypt_inner_payload(key: bytes, inner_name: str, encrypted_data: bytes) -> bytes:
    decrypted = decrypt_aes256_ecb(encrypted_data, key)
    if not verify_magic(decrypted):
        fail(f"inner firmware header magic mismatch for {inner_name}")
    payload_len = read_u32(decrypted, 0x10)
    end = 32 + payload_len
    if end > len(decrypted):
        fail(f"inner payload length overflow for {inner_name}: {payload_len:#x}")
    return decrypted[32:end]


def write_output(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    log(f"saved payload: {path}")


def print_download_progress(index: int, total_chunks: int) -> None:
    if index == 1:
        print("[*] download progress: ", end="", flush=True)
    print(".", end="", flush=True)
    if index == total_chunks:
        print(f" {total_chunks}/{total_chunks}", flush=True)


def passthru_fw_download(device: str, payload: Path, xfer: int, dry_run: bool) -> None:
    data = payload.read_bytes()
    if xfer <= 0 or xfer % 4:
        fail("--xfer must be a positive multiple of 4")
    if len(data) % 4:
        fail("payload size must be a multiple of 4 for NVMe firmware download")

    total_chunks = (len(data) + xfer - 1) // xfer
    log(f"starting firmware download to {device}: {len(data):,} bytes in {total_chunks} chunks")

    with tempfile.NamedTemporaryFile(prefix="nvme-fw-", suffix=".bin") as tmp:
        for index, offset in enumerate(range(0, len(data), xfer), start=1):
            chunk = data[offset : offset + xfer]
            tmp.seek(0)
            tmp.truncate(0)
            tmp.write(chunk)
            tmp.flush()

            numd = len(chunk) // 4
            cmd = [
                "nvme",
                "admin-passthru",
                device,
                f"--opcode={FW_DOWNLOAD_OPCODE}",
                "--namespace-id=0",
                f"--cdw10={numd - 1}",
                f"--cdw11={offset // 4}",
                f"--data-len={len(chunk)}",
                "--write",
                f"--input-file={tmp.name}",
            ]
            try:
                run(cmd, dry_run=dry_run)
            except subprocess.CalledProcessError as exc:
                if index > 1:
                    print(flush=True)
                stderr = exc.stderr.decode("utf-8", "ignore").strip()
                raise FlashError(stderr or f"firmware download failed at offset {offset:#x}")

            print_download_progress(index, total_chunks)


def passthru_fw_commit(device: str, slot: int, action: int, dry_run: bool) -> None:
    cdw10 = (slot & 0x7) | ((action & 0x7) << 3)
    cmd = [
        "nvme",
        "admin-passthru",
        device,
        f"--opcode={FW_COMMIT_OPCODE}",
        "--namespace-id=0",
        f"--cdw10={cdw10}",
    ]
    log(f"committing firmware to slot {slot} with action {action}")
    try:
        run(cmd, dry_run=dry_run)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "ignore").strip()
        raise FlashError(stderr or "firmware commit failed")


def save_payload_temporarily(payload: bytes) -> tempfile.NamedTemporaryFile:
    tmp = tempfile.NamedTemporaryFile(prefix="samsung-fw-", suffix=".bin", delete=False)
    tmp.write(payload)
    tmp.flush()
    tmp.close()
    return tmp


def flash_payload(device: str, payload_path: Path, xfer: int, slot_value: str, action: int, dry_run: bool) -> None:
    slots = resolve_slot_candidates(slot_value)

    if len(slots) == 1:
        slot = slots[0]
        log(f"flashing with slot {slot}")
        passthru_fw_download(device, payload_path, xfer, dry_run)
        passthru_fw_commit(device, slot, action, dry_run)
        return

    errors: list[str] = []
    for slot in slots:
        log(f"flashing with auto slot candidate {slot}")
        try:
            passthru_fw_download(device, payload_path, xfer, dry_run)
            passthru_fw_commit(device, slot, action, dry_run)
            log(f"slot {slot} succeeded")
            return
        except FlashError as exc:
            message = str(exc)
            errors.append(f"slot {slot}: {message}")
            log(f"slot {slot} failed: {message}")

    fail("all slot candidates failed: " + "; ".join(errors))


def do_extract(args: argparse.Namespace) -> tuple[str, bytes]:
    source = resolve_source(args)
    try:
        log(f"extracting AES key from fumagician ({source.source})")
        key = extract_key(source.fumagician, source.firmware)
        log("verified AES-256 key against outer package header")

        zip_data = decrypt_outer_zip(key, source.firmware)
        inner_names, total_records = inspect_outer_zip(zip_data)
        log(
            "decrypted outer package: "
            f"{len(inner_names)} unique inner images ({total_records} ZIP records total)"
        )

        rbuf, selector, selector_origin = resolve_selector(args)
        if rbuf:
            log(f"parsed selector {selector} from {selector_origin}: {rbuf}")
        else:
            log(f"using {selector_origin}")

        outer_name = source.firmware.stem
        inner_name, inner_encrypted = select_inner_entry(zip_data, outer_name, selector)
        log(f"selected inner firmware: {inner_name}")

        payload = decrypt_inner_payload(key, inner_name, inner_encrypted)
        log(f"decrypted selected payload: {len(payload):,} bytes")
        return inner_name, payload
    finally:
        source.cleanup()


def command_auto(args: argparse.Namespace) -> None:
    if not args.device:
        fail("--device is required for auto mode")

    inner_name, payload = do_extract(args)
    temp_path: Path | None = None

    if args.save_readbuffer:
        log(f"saved ReadBuffer dump: {args.save_readbuffer}")

    if args.output:
        write_output(args.output, payload)
        payload_path = args.output
    elif args.dry_run:
        payload_path = Path(f"{Path(inner_name).stem}.bin")
        write_output(payload_path, payload)
        log("dry run enabled: payload was extracted, but firmware commands will not be sent")
    else:
        tmp = save_payload_temporarily(payload)
        temp_path = Path(tmp.name)
        payload_path = temp_path
        log(f"saved selected payload to temporary file: {payload_path}")

    try:
        log(f"flashing payload: {payload_path}")
        flash_payload(args.device, payload_path, args.xfer, args.slot, args.action, args.dry_run)
        log(f"done: {inner_name}")
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


def command_extract(args: argparse.Namespace) -> None:
    inner_name, payload = do_extract(args)
    output = args.output or Path(f"{Path(inner_name).stem}.bin")
    write_output(output, payload)


def command_flash_existing(args: argparse.Namespace) -> None:
    if not args.payload.exists():
        fail(f"payload not found: {args.payload}")
    log(f"flashing existing payload: {args.payload}")
    flash_payload(args.device, args.payload, args.xfer, args.slot, args.action, args.dry_run)
    log("done")


def main() -> None:
    args = parse_args()

    if args.command == "auto":
        command_auto(args)
    elif args.command == "extract":
        command_extract(args)
    elif args.command == "flash-existing":
        command_flash_existing(args)
    else:
        fail(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
