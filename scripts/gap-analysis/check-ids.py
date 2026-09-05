#!/usr/bin/env python3
"""Every GA11 finding id must be sha1(our_ref + title[:60])[:8] of the record as committed.
Exit 1 on any mismatch, and list them. Run before committing a dim-*.json."""
import glob, hashlib, json, sys
bad = []
for path in sorted(glob.glob('docs/gap-analysis-11-data/dim-*.json')):
    for f in json.load(open(path))['findings']:
        want = hashlib.sha1((f['our_ref'] + f['title'][:60]).encode()).hexdigest()[:8]
        if want != f['id']:
            bad.append((path, f['id'], want))
for b in bad:
    print('MISMATCH %s: id %s, record hashes to %s' % b)
print('check-ids: %d findings checked, %d mismatches' % (
    sum(len(json.load(open(p))['findings']) for p in glob.glob('docs/gap-analysis-11-data/dim-*.json')), len(bad)))
sys.exit(1 if bad else 0)
