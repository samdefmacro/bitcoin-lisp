#!/usr/bin/env python3
"""The datadir interop differential: a regtest datadir one implementation
wrote, started by the other, and every block and index answer compared.

Two lanes, run by scripts/interop-test.sh through scripts/conformance.sh (Core's
own functional framework, with Core's previous releases mounted at /releases):

  ours-to-core  our node mines a chain (coinbase, P2TR, P2PK, P2WPKH, P2SH and
                OP_RETURN outputs, spends of them, and a two-block reorg) with
                -txindex -blockfilterindex -coinstatsindex, and records what
                it answers; Core v28.2 then starts on a copy of its blocks/
                and must answer the same, block by block;
  core-to-ours  the same chain shape mined by Core v28.2, then our node on the
                copy.

What is compared, per height of the active chain: getblockhash, getblockheader
and getblock verbosity 1 (the whole objects), getblockfilter (filter and header),
gettxoutsetinfo muhash at that height (the coinstats index), and for every
transaction getrawtransaction through the txindex and gettxoutproof. Then
getblockchaininfo's chain facts, getchaintips, and getindexinfo's synced
heights.

What is copied is blocks/ -- the blk/rev files and blocks/index, which are
Core's formats on both sides -- and nothing else by default; the consumer
builds its own indexes from the copied blocks and must answer the same:

  chainstate/  our coins database is not Core's format until batch coinsdb
               lands, so the consumer runs -reindex-chainstate;
               `--copy-chainstate' copies it and drops the flag.
  indexes/     only the best-block LOCATOR record of each index is Core's
               format here; the records are not (our txindex stores
               (block hash, position) where Core stores CDiskTxPos, our
               blockfilter index keeps header+filter by hash where Core keeps
               DBVal by height and hash plus fltr?????.dat files), and Core
               v28.2 refuses ours at start-up ("Cannot read last block filter
               header; index may be corrupted"). `--copy-indexes' copies them,
               for when the formats agree. The coinstats index cannot be
               shared with v28.2 at all: Core moved it from indexes/coinstats
               to indexes/coinstatsindex with a wider record after v29
               (index/coinstatsindex.cpp:93-101 at the pin).

Prints `INTEROP <lane> checks=<n>' per lane; any mismatch fails the test.
"""
from collections import Counter
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "refs", "bitcoin", "test", "functional"))

from decimal import Decimal  # noqa: E402

from test_framework.authproxy import JSONRPCException  # noqa: E402
from test_framework.messages import COIN, CTxOut  # noqa: E402
from test_framework.script import CScript, OP_RETURN, hash160  # noqa: E402
from test_framework.script_util import (  # noqa: E402
    key_to_p2wpkh_script,
    script_to_p2sh_script,
)
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402
from test_framework.wallet import MiniWallet, MiniWalletMode  # noqa: E402
from test_framework.wallet_util import generate_keypair  # noqa: E402

CORE_VERSION = 280200
INDEX_ARGS = ["-txindex=1", "-blockfilterindex=1", "-coinstatsindex=1"]
# Fields only the node that wrote the block files knows the same way: the
# on-disk size includes undo files the consumer may or may not rewrite, and
# the verification estimate is a clock-based guess.
CHAININFO_KEYS = ["chain", "blocks", "headers", "bestblockhash", "difficulty",
                  "time", "mediantime", "chainwork", "pruned"]
# gettxoutsetinfo keys both v28.2 and the pin report for the muhash form.
TXOUTSET_KEYS = ["height", "bestblock", "txouts", "bogosize", "muhash",
                 "total_amount", "total_unspendable_amount", "block_info"]


def differences(core, ours, gaps, rpc, path=""):
    """[(path, core-value, our-value)] where CORE and OURS disagree. A dict key
    only OUR side has is a field Core v28.2 predates (counted in GAPS, not a
    difference); every other disagreement is one."""
    if isinstance(core, dict) and isinstance(ours, dict):
        out = []
        for key in sorted(set(core) | set(ours)):
            if key not in core:
                gaps[(rpc, key)] += 1
            elif key not in ours:
                out.append((f"{path}.{key}", core[key], "<absent>"))
            else:
                out += differences(core[key], ours[key], gaps, rpc, f"{path}.{key}")
        return out
    if isinstance(core, list) and isinstance(ours, list) and len(core) == len(ours):
        out = []
        for i, (c, o) in enumerate(zip(core, ours)):
            out += differences(c, o, gaps, rpc, f"{path}[{i}]")
        return out
    return [] if core == ours else [(path, core, ours)]


def indexes_synced(node):
    """All three indexes are running and have caught up -- an EMPTY getindexinfo
    (a node started without them) is not synced."""
    info = node.getindexinfo()
    return len(info) == 3 and all(i["synced"] for i in info.values())


class DatadirInteropTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--copy-chainstate", dest="copy_chainstate",
                            default=False, action="store_true",
                            help="copy chainstate/ too and start the consumer "
                                 "WITHOUT -reindex-chainstate (once our coins "
                                 "database is Core's format)")
        parser.add_argument("--copy-indexes", dest="copy_indexes",
                            default=False, action="store_true",
                            help="copy indexes/ too (once the index records are "
                                 "Core's format), instead of letting the consumer "
                                 "build its own")
        parser.add_argument("--lane", dest="lanes", action="append",
                            choices=["ours-to-core", "core-to-ours"],
                            help="run only this lane (repeatable; default both)")

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        # 0: ours producing, 1: Core consuming; 2: Core producing, 3: ours consuming.
        self.extra_args = [INDEX_ARGS] * 4

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args,
                       versions=[None, CORE_VERSION, CORE_VERSION, None])

    # --- producing -----------------------------------------------------------

    def mine_chain(self, node):
        """A regtest chain with every output type the indexes treat differently,
        and a reorg, so blocks/index holds a stale branch too."""
        noop = self.no_op
        taproot = MiniWallet(node)
        p2pk = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
        self.generate(taproot, 10, sync_fun=noop)
        self.generate(p2pk, 10, sync_fun=noop)
        self.generate(node, 100, sync_fun=noop)
        taproot.rescan_utxos()
        p2pk.rescan_utxos()
        _, pubkey = generate_keypair()
        for round_ in range(6):
            for _ in range(3):
                taproot.send_self_transfer(from_node=node)
                p2pk.send_self_transfer(from_node=node)
            taproot.send_to(from_node=node, scriptPubKey=key_to_p2wpkh_script(pubkey),
                            amount=COIN // 10)
            taproot.send_to(from_node=node,
                            scriptPubKey=script_to_p2sh_script(CScript([hash160(pubkey)])),
                            amount=COIN // 20)
            # An unspendable output: coinstats counts it under unspendables.
            # Burning needs -maxburnamount's consent, as it does in Core.
            burn = 1000 * (round_ + 1)
            tx = taproot.create_self_transfer()["tx"]
            tx.vout[0].nValue -= burn
            tx.vout.append(CTxOut(burn, CScript([OP_RETURN, b"interop"])))
            taproot.sendrawtransaction(from_node=node, tx_hex=tx.serialize().hex(),
                                       maxburnamount=Decimal(burn) / COIN)
            self.generate(node, 1, sync_fun=noop)
        # A two-block branch replaced by a three-block one.
        tip = node.getbestblockhash()
        stale = self.generate(node, 2, sync_fun=noop)
        node.invalidateblock(stale[0])
        # To another address: the same template in the same second is the
        # invalidated block again, which Core refuses as a duplicate-invalid.
        self.generate(taproot, 3, sync_fun=noop)
        node.reconsiderblock(stale[0])
        assert tip != node.getbestblockhash()
        # The stale branch is really there to be copied and compared.
        assert_equal(len(node.getchaintips()), 2)
        self.wait_until(lambda: indexes_synced(node))

    def record(self, node):
        """Everything the consumer must answer the same, keyed by question."""
        answers = {}
        height = node.getblockcount()
        for h in range(height + 1):
            bhash = node.getblockhash(h)
            answers[("getblockhash", h)] = bhash
            answers[("getblockheader", bhash)] = node.getblockheader(bhash)
            block = node.getblock(bhash, 1)
            answers[("getblock", bhash)] = block
            answers[("getblockfilter", bhash)] = node.getblockfilter(bhash)
            info = node.gettxoutsetinfo("muhash", h)
            answers[("gettxoutsetinfo", h)] = {k: info.get(k) for k in TXOUTSET_KEYS}
            # The genesis coinbase is in no index (txindex.cpp skips it).
            for txid in block["tx"] if h > 0 else []:
                answers[("getrawtransaction", txid)] = node.getrawtransaction(txid)
                answers[("gettxoutproof", txid)] = node.gettxoutproof([txid])
        chain = node.getblockchaininfo()
        answers[("getblockchaininfo",)] = {k: chain[k] for k in CHAININFO_KEYS}
        answers[("getchaintips",)] = sorted(node.getchaintips(), key=lambda t: t["hash"])
        answers[("getindexinfo",)] = {name: (i["synced"], i["best_block_height"])
                                      for name, i in node.getindexinfo().items()}
        return answers

    # --- consuming -----------------------------------------------------------

    def copy_datadir(self, src, dst):
        dirs = (["blocks"]
                + (["indexes"] if self.options.copy_indexes else [])
                + (["chainstate"] if self.options.copy_chainstate else []))
        for d in dirs:
            target = dst.chain_path / d
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(src.chain_path / d, target)

    def ask(self, node, question):
        name, *args = question
        if name == "getblock":
            return node.getblock(args[0], 1)
        if name == "gettxoutsetinfo":
            info = node.gettxoutsetinfo("muhash", args[0])
            return {k: info.get(k) for k in TXOUTSET_KEYS}
        if name == "gettxoutproof":
            return node.gettxoutproof([args[0]])
        if name == "getblockchaininfo":
            chain = node.getblockchaininfo()
            return {k: chain[k] for k in CHAININFO_KEYS}
        if name == "getchaintips":
            return sorted(node.getchaintips(), key=lambda t: t["hash"])
        if name == "getindexinfo":
            return {n: (i["synced"], i["best_block_height"])
                    for n, i in node.getindexinfo().items()}
        return getattr(node, name)(*args)

    def run_lane(self, lane, producer, consumer):
        self.log.info(f"{lane}: node{producer.index} mines and records")
        producer.start()
        producer.wait_for_rpc_connection()
        self.mine_chain(producer)
        answers = self.record(producer)
        height = producer.getblockcount()
        producer.stop_node()

        self.log.info(f"{lane}: node{consumer.index} starts on the copy")
        self.copy_datadir(producer, consumer)
        # start(extra_args=...) REPLACES the node's own extra_args.
        extra = INDEX_ARGS + ([] if self.options.copy_chainstate else ["-reindex-chainstate"])
        consumer.start(extra_args=extra)
        consumer.wait_for_rpc_connection()
        self.wait_until(lambda: consumer.getblockcount() == height, timeout=300)
        self.wait_until(lambda: indexes_synced(consumer), timeout=300)

        # Which side is Core v28.2: a field only the PIN reports (getblockheader's
        # `target', new in v29) is a version gap there, not a divergence; a
        # field only Core reports is ours missing.
        core_is_consumer = consumer.version is not None
        mismatches = []
        gaps = Counter()
        for question, want in answers.items():
            try:
                got = self.ask(consumer, question)
            except JSONRPCException as e:
                got = {"rpc-error": e.error}
            core, ours = (got, want) if core_is_consumer else (want, got)
            diffs = differences(core, ours, gaps, question[0])
            if diffs:
                mismatches.append((question, diffs))
        kinds = Counter((q[0], path) for q, diffs in mismatches for path, _, _ in diffs)
        for (rpc, path), n in sorted(kinds.items()):
            example = next((q, d) for q, ds in mismatches for d in ds
                           if q[0] == rpc and d[0] == path)
            self.log.error(f"{lane}: {n} x {rpc}{path}: core {example[1][1]!r} ours "
                           f"{example[1][2]!r} (first at {example[0][1:]})")
        for (rpc, key), n in sorted(gaps.items()):
            self.log.info(f"{lane}: version gap, {n} x {rpc}.{key} only at the pin")
        consumer.stop_node()
        print(f"INTEROP {lane} checks={len(answers)} mismatches={len(mismatches)}", flush=True)
        assert_equal(len(mismatches), 0)
        return len(answers)

    def run_test(self):
        lanes = self.options.lanes or ["ours-to-core", "core-to-ours"]
        total = 0
        if "ours-to-core" in lanes:
            total += self.run_lane("ours-to-core", self.nodes[0], self.nodes[1])
        if "core-to-ours" in lanes:
            total += self.run_lane("core-to-ours", self.nodes[2], self.nodes[3])
        print(f"INTEROP total checks={total}", flush=True)


if __name__ == "__main__":
    DatadirInteropTest(__file__).main()
