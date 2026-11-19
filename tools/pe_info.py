import struct, sys, os, json, datetime

def sections(d):
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    mach, nsec = struct.unpack_from('<HH', d, pe + 4)
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    entry = struct.unpack_from('<I', d, opt + 16)[0]
    imagebase = struct.unpack_from('<Q', d, opt + 24)[0]
    subsystem = struct.unpack_from('<H', d, opt + 68)[0]
    dllchar = struct.unpack_from('<H', d, opt + 70)[0]
    so = opt + optsz
    out = []
    for i in range(nsec):
        off = so + i * 40
        name = d[off:off + 8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, ra = struct.unpack_from('<IIII', d, off + 8)
        chars = struct.unpack_from('<I', d, off + 36)[0]
        out.append(dict(name=name, vsize=vs, vaddr=hex(va), rawsize=rs, rawoff=hex(ra), chars=hex(chars)))
    return dict(machine=hex(mach), entry=hex(entry + imagebase), imagebase=hex(imagebase),
                subsystem=subsystem, dllchar=hex(dllchar), sec=out)

def resources(path):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    res = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            tname = str(e.name) if e.name else pefile.RESOURCE_TYPE.get(e.struct.Id, str(e.struct.Id))
            d1 = getattr(e, 'directory', None)
            if not d1:
                continue
            for s in d1.entries:
                d2 = getattr(s, 'directory', None)
                if not d2:
                    continue
                for l in d2.entries:
                    res.append(dict(type=tname, id=s.struct.Id, lang=l.struct.Id, size=l.data.struct.Size))
    ver = []
    try:
        if hasattr(pe, 'FileInfo'):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                ver.append('%s=%s' % (k.decode('utf-8', 'ignore'), v.decode('utf-8', 'ignore')))
    except Exception as exc:
        ver.append('version parse error %s' % exc)
    imports = []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(dict(dll=entry.dll.decode('utf-8', 'ignore'),
                                funcs=[f.name.decode('utf-8', 'ignore') for f in entry.imports if f.name]))
    except Exception as exc:
        imports.append(dict(dll='error', funcs=[str(exc)]))
    return dict(resources=res, version=ver, imports=imports,
                pe_machine=hex(pe.FILE_HEADER.Machine), timestamp=pe.FILE_HEADER.TimeDateStamp,
                compile_time=str(datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)))

def main():
    path, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    d = open(path, 'rb').read()
    info = sections(d)
    try:
        info.update(resources(path))
    except Exception as exc:
        info['pefile_error'] = str(exc)
    with open(os.path.join(outdir, 'pe_info.json'), 'w', encoding='utf-8') as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print('sections:')
    for s in info['sec']:
        print('  %-10s vsize=%9d vaddr=%s rawsize=%9d' % (s['name'], s['vsize'], s['vaddr'], s['rawsize']))
    print('compile_time', info.get('compile_time'))
    for v in info.get('version', []):
        print('ver', v)
    for im in info.get('imports', []):
        print('imp', im['dll'], len(im['funcs']))

if __name__ == '__main__':
    main()
