import re, os, sys, json

ANCHOR = b'<!DOCTYPE html>'

def main():
    path, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    d = open(path, 'rb').read()
    fe = os.path.join(outdir, 'frontend')
    os.makedirs(fe, exist_ok=True)
    found = []
    start = d.find(ANCHOR)
    while start >= 0:
        end = d.find(b'</html>', start)
        if end < 0:
            break
        blob = d[start:end + 7]
        name = 'index_%d.html' % len(found)
        open(os.path.join(fe, name), 'wb').write(blob)
        found.append(dict(offset=start, size=len(blob), file=name))
        start = d.find(ANCHOR, end)
    report = dict(html_blocks=found)

    js = []
    for m in re.finditer(rb'<script[^>]*>', d):
        s = m.end()
        e = d.find(b'</script>', s)
        if e < 0 or e - s > 8_000_000:
            continue
        js.append(dict(offset=s, size=e - s))
    report['script_blocks'] = js

    css = []
    for m in re.finditer(rb'<style[^>]*>', d):
        s = m.end()
        e = d.find(b'</style>', s)
        if e < 0 or e - s > 8_000_000:
            continue
        css.append(dict(offset=s, size=e - s))
    report['style_blocks'] = css

    printable = re.findall(rb'[\x20-\x7e]{8,}', d)
    utf8 = re.findall(rb'(?:[\xe4-\xe9][\x80-\xbf]{2}|[\x20-\x7e]){6,}', d)
    with open(os.path.join(outdir, 'strings_ascii.txt'), 'w', encoding='utf-8', errors='replace') as f:
        for s in printable:
            f.write(s.decode('latin1') + '\n')
    with open(os.path.join(outdir, 'strings_utf8.txt'), 'w', encoding='utf-8', errors='replace') as f:
        for s in utf8:
            try:
                t = s.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if any('\u4e00' <= c <= '\u9fff' for c in t):
                f.write(t + '\n')

    urls = sorted(set(m.decode('latin1') for m in re.findall(rb'https?://[\x21-\x7e]{4,120}', d)))
    ips = sorted(set(m.decode('latin1') for m in re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b', d)))
    apis = sorted(set(m.decode('latin1') for m in re.findall(rb'/(?:api|v[0-9]|admin|auth|login|user|chat|tool)[a-zA-Z0-9_/\-\.]{0,60}', d)))
    paths = sorted(set(m.decode('latin1') for m in re.findall(rb'[A-Za-z]:[\\/][\x20-\x7e]{3,120}', d)))
    report['urls'] = urls
    report['ips'] = ips
    report['api_paths'] = apis[:4000]
    report['win_paths'] = paths[:2000]

    pkgs = sorted(set(m.decode('latin1') for m in re.findall(rb'(?:[a-z0-9_]+/){2,5}[a-z0-9_]+', d) if len(m) < 120))
    report['path_like'] = pkgs[:6000]

    json.dump(report, open(os.path.join(outdir, 'extract_report.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print('html blocks', found)
    print('scripts', js)
    print('styles', css)
    print('urls', len(urls), 'ips', len(ips), 'api', len(apis))

if __name__ == '__main__':
    main()
