#!/usr/bin/env bash
# scripts/ops/soak-report.sh [DAYS]: summarise the server's soak.tsv from the host.
# Prints, per node: first/last sample, height progress, peer min/max, RSS min/max,
# restarts (etime going backwards), and new [error] lines between samples.
set -u
DAYS=${1:-7}
S="ssh -o ConnectTimeout=20 -o BatchMode=yes test-bitcoin-server"
$S "cat /data/bitcoin-lisp/logs/soak.tsv" | python3 -c '
import sys, datetime
days=float(sys.argv[1])
cut=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)-datetime.timedelta(days=days)
rows=[l.rstrip("\n").split("\t") for l in sys.stdin if l.strip()]
def et(s):
    if "-" in s: d,rest=s.split("-"); 
    else: d,rest=0,s
    p=[int(x) for x in rest.split(":")]
    while len(p)<3: p=[0]+p
    return int(d)*86400+p[0]*3600+p[1]*60+p[2]
for net in ("testnet4","mainnet"):
    r=[x for x in rows if x[1]==net and datetime.datetime.strptime(x[0],"%Y-%m-%dT%H:%M:%SZ")>=cut]
    print(f"== {net}: {len(r)} samples")
    if not r: continue
    print(f"  first {r[0][0]} h={r[0][3]} peers={r[0][6]} rss={r[0][7]}MiB rev={r[0][2]}")
    print(f"  last  {r[-1][0]} h={r[-1][3]}/{r[-1][4]} ibd={r[-1][5]} peers={r[-1][6]} rss={r[-1][7]}MiB rev={r[-1][2]}")
    ok=[x for x in r if x[3].isdigit()]
    down=[x[0] for x in r if not x[3].isdigit()]
    if down: print(f"  RPC DOWN at: {down}")
    if ok:
        print(f"  peers min/max {min(int(x[6]) for x in ok)}/{max(int(x[6]) for x in ok)}  rss min/max {min(int(x[7]) for x in ok if x[7].isdigit())}/{max(int(x[7]) for x in ok if x[7].isdigit())} MiB")
        lag=[x[0] for x in ok if int(x[4])-int(x[3])>2]
        if lag: print(f"  behind headers by >2 at: {lag}")
    restarts=[r[i][0] for i in range(1,len(r)) if r[i][8]!="no-process" and r[i-1][8]!="no-process" and et(r[i][8])<et(r[i-1][8])]
    print(f"  restarts: {restarts or "none"}")
    errs=[(r[i][0], int(r[i][9])-int(r[i-1][9])) for i in range(1,len(r)) if r[i][9].isdigit() and r[i-1][9].isdigit() and int(r[i][9])>int(r[i-1][9])]
    print(f"  new [error] lines: {errs or "none"}")
    reorgs=[(r[i][0], int(r[i][11])-int(r[i-1][11])) for i in range(1,len(r)) if r[i][11].isdigit() and r[i-1][11].isdigit() and int(r[i][11])>int(r[i-1][11])]
    print(f"  reorg mentions: {reorgs or "none"}")
' "$DAYS"
