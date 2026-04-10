from pathlib import Path
import ast
import struct

ROOT = Path(__file__).resolve().parent.parent
LOCALES_DIR = ROOT / 'locales'


def unquote_po(s: str) -> str:
    return ast.literal_eval(s)


def parse_po(path: Path):
    messages = {}
    msgid = None
    msgstr = None
    state = None

    def commit():
        nonlocal msgid, msgstr
        if msgid is not None and msgstr is not None:
            messages[msgid] = msgstr
        msgid = None
        msgstr = None

    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line:
            commit()
            state = None
            continue
        if line.startswith('#'):
            continue
        if line.startswith('msgid '):
            if msgid is not None and msgstr is not None:
                commit()
            msgid = unquote_po(line[6:])
            msgstr = None
            state = 'msgid'
            continue
        if line.startswith('msgstr '):
            msgstr = unquote_po(line[7:])
            state = 'msgstr'
            continue
        if line.startswith('"'):
            text = unquote_po(line)
            if state == 'msgid' and msgid is not None:
                msgid += text
            elif state == 'msgstr' and msgstr is not None:
                msgstr += text
            continue
    if msgid is not None and msgstr is not None:
        commit()
    return messages


def write_mo(messages, output_path: Path):
    items = sorted(messages.items())
    ids = []
    strs = []
    for msgid, msgstr in items:
        ids.append(msgid.encode('utf-8'))
        strs.append(msgstr.encode('utf-8'))

    keystart = 7 * 4 + len(items) * 8 * 2
    id_offset = keystart
    str_offset = id_offset + sum(len(i) + 1 for i in ids)

    koffsets = []
    offset = id_offset
    for msgid in ids:
        koffsets.append((len(msgid), offset))
        offset += len(msgid) + 1

    toffsets = []
    offset = str_offset
    for msgstr in strs:
        toffsets.append((len(msgstr), offset))
        offset += len(msgstr) + 1

    with output_path.open('wb') as fp:
        fp.write(struct.pack('Iiiiiii', 0x950412de, 0, len(items), 28, 28 + len(items) * 8, 0, 0))
        for length, offset in koffsets:
            fp.write(struct.pack('ii', length, offset))
        for length, offset in toffsets:
            fp.write(struct.pack('ii', length, offset))
        for msgid in ids:
            fp.write(msgid + b'\0')
        for msgstr in strs:
            fp.write(msgstr + b'\0')


def main():
    for po_path in sorted(LOCALES_DIR.glob('*.po')):
        messages = parse_po(po_path)
        mo_path = po_path.with_suffix('.mo')
        write_mo(messages, mo_path)
        print(f'Generated {mo_path.name}')


if __name__ == '__main__':
    main()
