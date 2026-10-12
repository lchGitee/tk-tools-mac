#!/usr/bin/env python3
"""从安装包已解出的 ASAR 和旁置资源恢复可编辑应用；不执行目标程序。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('asar', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--unpacked', type=Path)
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=True)
with args.asar.open('rb') as stream:
    prefix = stream.read(16)
    if len(prefix) != 16:
        raise ValueError('ASAR 头不完整')
    _, header_size, _, json_size = struct.unpack('<4I', prefix)
    header = json.loads(stream.read(json_size))
    base = 8 + header_size
    records = []
    def restore(files, parent=Path()):
        for name, entry in files.items():
            relative = parent / name
            target = root / relative
            if not target.resolve().is_relative_to(root):
                raise ValueError(f'路径超出恢复目录: {relative}')
            if 'files' in entry:
                restore(entry['files'], relative)
                continue
            if 'link' in entry:
                raise ValueError(f'需单独处理符号链接: {relative}')
            if entry.get('unpacked'):
                if args.unpacked is None:
                    raise ValueError(f'缺少旁置资源目录: {relative}')
                content = (args.unpacked / relative).read_bytes()
            else:
                stream.seek(base + int(entry['offset']))
                content = stream.read(entry['size'])
            if len(content) != entry['size']:
                raise ValueError(f'文件长度不符: {relative}')
            # 原包声明完整性时逐文件验证，避免把截断内容当作恢复成功。
            digest = hashlib.sha256(content).hexdigest()
            integrity = entry.get('integrity')
            if integrity:
                if integrity.get('algorithm') != 'SHA256' or digest != integrity['hash']:
                    raise ValueError(f'文件完整性不符: {relative}')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            records.append({'path': relative.as_posix(), 'size': len(content), 'sha256': digest, 'unpacked': bool(entry.get('unpacked'))})
    restore(header['files'])
(root.parent.parent / 'restoration-manifest.json').write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'已恢复并验证 {len(records)} 个文件')
