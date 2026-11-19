import os, re, sys, json

HDR = re.compile(r'^/\* ===== (.+?) @ ([0-9a-fA-F]+) size=(\d+) ===== \*/$')

def main():
    outdir = sys.argv[1]
    cdir = os.path.join(outdir, 'c')
    funcs = []
    failed = []
    files = sorted(f for f in os.listdir(cdir)) if os.path.isdir(cdir) else []
    for fn in files:
        if not fn.endswith('.c'):
            continue
        cur = None
        buf = []
        for line in open(os.path.join(cdir, fn), encoding='utf-8', errors='replace'):
            if line.startswith('/* ===== ') and line.rstrip().endswith(' ===== */'):
                if cur:
                    funcs.append((cur, len(buf)))
                cur = line.rstrip()[10:-8].strip()
                buf = []
                continue
            if cur is None:
                continue
            if line.startswith('/* DECOMPILE_FAILED') or line.startswith('/* EXCEPTION'):
                failed.append(cur)
            buf.append(line)
        if cur:
            funcs.append((cur, len(buf)))
    lines = []
    lines.append('# decompiled function index')
    lines.append('total_blocks: %d' % len(funcs))
    lines.append('failed: %d' % len(failed))
    lines.append('')
    for name, n in funcs:
        lines.append('%s\t%d' % (name, n))
    open(os.path.join(outdir, 'index.txt'), 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    open(os.path.join(outdir, 'failed.txt'), 'w', encoding='utf-8').write('\n'.join(failed) + '\n')
    print('blocks', len(funcs), 'failed', len(failed), 'shards', len(files))
    for fn in files:
        p = os.path.join(cdir, fn)
        print(' ', fn, os.path.getsize(p))

if __name__ == '__main__':
    main()
