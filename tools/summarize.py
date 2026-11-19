import json, sys, os, collections

def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    raw = json.load(open(src, encoding='utf-8'))
    summary = {}
    funcs = []
    for key in ('UserFunctions', 'StdFunctions'):
        for f in raw.get(key, []) or []:
            name = f.get('FullName') or f.get('Name')
            funcs.append(dict(name=name, start=f.get('Start'), end=f.get('End'), pkg=key))
    summary['func_count'] = len(funcs)
    summary['build'] = raw.get('BuildInfo') or raw.get('Version')
    summary['arch'] = raw.get('Arch')
    summary['os'] = raw.get('OS')
    packages = collections.Counter()
    for f in funcs:
        n = f['name'] or ''
        p = n.rsplit('.', 1)[0] if '.' in n else n
        packages[p] += 1
    summary['top_packages'] = packages.most_common(80)
    files = raw.get('Files') or []
    summary['source_files'] = files
    modified = [f for f in files if 'go/pkg/mod' not in f and '/go/src/' not in f]
    summary['project_source_files'] = modified
    mainfuncs = sorted(set(f['name'] for f in funcs if (f['name'] or '').startswith('main.')))
    summary['main_functions'] = mainfuncs
    with open(os.path.join(outdir, 'functions_all.txt'), 'w', encoding='utf-8') as fh:
        for f in funcs:
            fh.write('%s %s %s\n' % (f['name'], f['start'], f['end']))
    with open(os.path.join(outdir, 'main_functions.txt'), 'w', encoding='utf-8') as fh:
        for n in mainfuncs:
            fh.write(n + '\n')
    with open(os.path.join(outdir, 'source_files.txt'), 'w', encoding='utf-8') as fh:
        for n in modified:
            fh.write(n + '\n')
    with open(os.path.join(outdir, 'packages.txt'), 'w', encoding='utf-8') as fh:
        for p, c in packages.most_common():
            fh.write('%6d  %s\n' % (c, p))
    types = raw.get('Types') or []
    summary['type_count'] = len(types)
    with open(os.path.join(outdir, 'types.txt'), 'w', encoding='utf-8') as fh:
        for t in types:
            fh.write(str(t.get('Name') or t) + '\n')
    json.dump(summary, open(os.path.join(outdir, 'summary.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
    print('functions', len(funcs), 'main', len(mainfuncs), 'types', len(types))
    print('project files', len(modified))
    for n in modified[:60]:
        print('  src', n)
    for n in mainfuncs[:200]:
        print('  main', n)

if __name__ == '__main__':
    main()
