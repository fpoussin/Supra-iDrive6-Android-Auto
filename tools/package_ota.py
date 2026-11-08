#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Required Notice: Copyright (c) 2026 nanaisu - NBT-AAD (https://github.com/Sq00ky/Supra-iDrive6-Android-Auto)
"""Create a signed NBT-AAD executable update using a private RSA PEM key."""
import argparse
import hashlib
import re
import struct
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key', required=True, type=Path, help='private RSA PEM key, kept outside the repository')
    parser.add_argument('--version', required=True, help='build identifier')
    parser.add_argument('--binary', required=True, type=Path, help='QNX ARM nbt-aad executable')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', args.version):
        parser.error('version must contain 1-80 letters, digits, dots, underscores or hyphens')
    binary = args.binary.read_bytes()
    if not 52 <= len(binary) <= 32 * 1024 * 1024 or binary[:6] != b'\x7fELF\x01\x01' or binary[16:20] != b'\x02\x00\x28\x00':
        parser.error('binary must be a 32-bit little-endian ARM executable under 32 MiB')
    manifest = ('NBT-AAD-OTA-1\nversion=%s\nsha256=%s\n' %
                (args.version, hashlib.sha256(binary).hexdigest())).encode('ascii')
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(args.key)],
                               input=manifest, check=True, stdout=subprocess.PIPE).stdout
    if not 1 <= len(signature) <= 1024:
        parser.error('signature size unsupported')
    args.output.write_bytes(b'NBTOTA1\n' + struct.pack('>III', len(manifest), len(signature), len(binary)) +
                            manifest + signature + binary)


if __name__ == '__main__':
    main()
