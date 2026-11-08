#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Required Notice: Copyright (c) 2026 nanaisu - NBT-AAD (https://github.com/Sq00ky/Supra-iDrive6-Android-Auto)
"""Exercise the producer and verifier together using disposable signing keys."""
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = r'''
#include "milestone-7/rhmiapp/update_package.hpp"
#include <fstream>
#include <iterator>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    std::ifstream k(argv[1]);
    std::string key((std::istreambuf_iterator<char>(k)), std::istreambuf_iterator<char>());
    FILE* f = fopen(argv[2], "rb");
    if (!f) return 2;
    std::string version, error;
    bool ok = nbt::update::verify(f, key.c_str(), version, error);
    fclose(f);
    return ok && version == "test-1" ? 0 : 1;
}
'''


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)


with tempfile.TemporaryDirectory() as temp:
    d = Path(temp)
    (d / 'test.cpp').write_text(SOURCE)
    run('g++', '-std=c++11', '-Wno-deprecated-declarations', '-I', str(ROOT), str(d / 'test.cpp'), '-lcrypto', '-o', str(d / 'verify'))
    for suffix in ('', 'other'):
        run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(d / ('key' + suffix)))
        run('openssl', 'pkey', '-in', str(d / ('key' + suffix)), '-pubout', '-out', str(d / ('pub' + suffix)))
    elf = bytearray(100)
    elf[:6] = b'\x7fELF\x01\x01'
    elf[16:20] = b'\x02\x00\x28\x00'
    (d / 'binary').write_bytes(elf)
    run('python3', str(ROOT / 'tools/package_ota.py'), '--key', str(d / 'key'), '--version', 'test-1',
        '--binary', str(d / 'binary'), '--output', str(d / 'package'))
    run(str(d / 'verify'), str(d / 'pub'), str(d / 'package'))
    def rejected(data, key='pub'):
        (d / 'bad').write_bytes(data)
        assert subprocess.run([str(d / 'verify'), str(d / key), str(d / 'bad')]).returncode == 1
    package = (d / 'package').read_bytes()
    rejected(package, 'pubother')
    rejected(package[:-1])
    rejected(package + b'x')
    changed = bytearray(package)
    changed[-1] ^= 1
    rejected(changed)
    changed = bytearray(package)
    changed[30] ^= 1
    rejected(changed)
    print('test_update_package: passed')
