import struct, sys, os, re, json, collections

def parse_at(d, base):
    if base + 72 > len(d):
        return None
    magic = struct.unpack_from('<I', d, base)[0]
    if magic not in (0xfffffff1, 0xfffffff0, 0xfffffffa, 0xfffffffb):
        return None
    if d[base + 7] != 8:
        return None
    nfunc = struct.unpack_from('<Q', d, base + 8)[0]
    nfiles = struct.unpack_from('<Q', d, base + 16)[0]
    textstart = struct.unpack_from('<Q', d, base + 24)[0]
    funcname_off = struct.unpack_from('<Q', d, base + 32)[0]
    cu_off = struct.unpack_from('<Q', d, base + 40)[0]
    filetab_off = struct.unpack_from('<Q', d, base + 48)[0]
    pctab_off = struct.unpack_from('<Q', d, base + 56)[0]
    pcln_off = struct.unpack_from('<Q', d, base + 64)[0]
    if not (0 < nfunc <= 3000000) or nfiles > 3000000:
        return None
    names_base = base + funcname_off
    ftab = base + pcln_off
    if ftab + 8 > len(d):
        return None
    name_limit = cu_off - funcname_off if cu_off > funcname_off else 1 << 20
    names = []
    for i in range(nfunc):
        off = ftab + i * 8
        if off + 8 > len(d):
            break
        entryoff, funcoff = struct.unpack_from('<II', d, off)
        fbase = base + pcln_off + funcoff
        if fbase + 8 > len(d):
            continue
        nameoff = struct.unpack_from('<i', d, fbase + 4)[0]
        if nameoff < 0 or nameoff >= name_limit:
            continue
        s = names_base + nameoff
        if s >= len(d):
            continue
        e = d.find(b'\x00', s, s + 400)
        if e < 0:
            continue
        try:
            nm = d[s:e].decode('utf-8')
        except UnicodeDecodeError:
            continue
        if not nm or len(nm) > 300:
            continue
        names.append((textstart + entryoff, nm))
    return dict(base=base, magic=hex(magic), nfunc=nfunc, nfiles=nfiles,
                textstart=textstart, funcname_off=funcname_off, cu_off=cu_off,
                filetab_off=filetab_off, pctab_off=pctab_off, pcln_off=pcln_off, names=names)

def find_all(d):
    out = []
    for magic in (b'\xf1\xff\xff\xff', b'\xf0\xff\xff\xff', b'\xfa\xff\xff\xff', b'\xfb\xff\xff\xff'):
        i = d.find(magic)
        while i >= 0:
            out.append(i)
            i = d.find(magic, i + 1)
    return out

def main():
    path, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    d = open(path, 'rb').read()
    best = None
    for cand in find_all(d):
        info = parse_at(d, cand)
        if not info:
            continue
        if len(info['names']) < 10:
            continue
        if best is None or len(info['names']) > len(best['names']):
            best = info
    if not best:
        print('no pclntab found')
        return
    names = best['names']
    print('pclntab base', hex(best['base']), 'magic', best['magic'])
    print('nfunc', best['nfunc'], 'nfiles', best['nfiles'], 'parsed', len(names))
    print('textstart', hex(best['textstart']))
    with open(os.path.join(outdir, 'pclntab_functions.txt'), 'w', encoding='utf-8') as fh:
        for addr, nm in names:
            fh.write('%016x\t%s\n' % (addr, nm))
    pk = collections.Counter()
    for _, nm in names:
        p = nm.rsplit('.', 1)[0] if '.' in nm else nm
        pk[p] += 1
    with open(os.path.join(outdir, 'pclntab_packages.txt'), 'w', encoding='utf-8') as fh:
        for p, c in pk.most_common():
            fh.write('%6d  %s\n' % (c, p))
    for tag, pred in (('main', lambda n: n.startswith('main.')),
                      ('project', lambda n: re.search(r'fengqi|toolbox|napcat', n, re.I) is not None)):
        sel = sorted(set(nm for _, nm in names if pred(nm)))
        with open(os.path.join(outdir, 'pclntab_%s.txt' % tag), 'w', encoding='utf-8') as fh:
            for n in sel:
                fh.write(n + '\n')
        print(tag, 'funcs', len(sel))
    json.dump(dict(base=hex(best['base']), nfunc=best['nfunc'], nfiles=best['nfiles'],
                   parsed=len(names), textstart=hex(best['textstart'])),
              open(os.path.join(outdir, 'pclntab_info.json'), 'w'), indent=2)
    print('packages', len(pk))

if __name__ == '__main__':
    main()
