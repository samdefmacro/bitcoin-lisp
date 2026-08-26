#!/usr/bin/env python3
"""How long does ONE block take to reach two peers? wallet_basic.py calls
generate+sync_all about thirty times; at 30s each that is the timeout."""
import sys, time
sys.path.insert(0, '/workspace/refs/bitcoin/test/functional')
from test_framework.test_framework import BitcoinTestFramework

class PropProbe(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        addr = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw"
        for i in range(5):
            t = time.time()
            self.generatetoaddress(self.nodes[0], 1, addr, sync_fun=self.no_op)
            mined = time.time() - t
            t = time.time()
            self.sync_blocks(timeout=60)
            self.log.info("ROUND %d mine=%.2fs propagate=%.2fs" % (i, mined, time.time() - t))

if __name__ == '__main__':
    PropProbe(__file__).main()
