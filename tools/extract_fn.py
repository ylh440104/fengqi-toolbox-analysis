import sys, re, glob, os
def main():
    pattern = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else None
    buf = []
    for p in sorted(glob.glob('results/c/*.c')):
        data = open(p, encoding='utf-8', errors='replace').read()
        parts = re.split(r'\n/\* ===== ', data)
        for part in parts[1:]:
            e = part.find(' ===== */')
            if e < 0:
                continue
            hdr = part[:e]
            if re.search(pattern, hdr):
                buf.append('/* ===== ' + part[:e + 9] + part[e + 9:])
    text = '\n'.join(buf)
    if outfile:
        open(outfile, 'w', encoding='utf-8').write(text)
        print('wrote', outfile, len(text))
    else:
        print(text[:6000])
if __name__ == '__main__':
    main()
