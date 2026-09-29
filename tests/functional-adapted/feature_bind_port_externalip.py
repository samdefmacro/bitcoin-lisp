#!/usr/bin/env python3
"""feature_bind_port_externalip.py with the pinned framework's two interferences
removed: test_node.py:274-277 appends -bind=0.0.0.0:P / -bind=127.0.0.1:T=onion
to a node given no -bind (so Core's bind_on_any, init.cpp:2163, is false and
Discover() never runs), and setup_network connects the nodes over 127.0.0.1
ports they do not listen on. The assertions are Core's, unchanged."""
import os
import sys

# Core's own test, imported from the pinned reference checkout (refs/bitcoin at
# the project's pin); only the two framework steps below are replaced.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', 'refs', 'bitcoin', 'test', 'functional'))
from feature_bind_port_externalip import BindPortExternalIPTest


class Copy(BindPortExternalIPTest):
    def set_test_params(self):
        BindPortExternalIPTest.set_test_params(self)

    def run_test(self):
        BindPortExternalIPTest.run_test(self)

    def setup_network(self):
        # Replaced step 1, test_node.py:274-277: a node with no -bind gets
        # -bind=0.0.0.0:P and -bind=127.0.0.1:T=onion appended, which makes
        # Core's bind_on_any (init.cpp:2163) false; has_explicit_bind stops it.
        # Replaced step 2, test_framework.py:360-378 (setup_network ->
        # connect_nodes): nodes bound to 1.1.1.1 are not dialled over
        # 127.0.0.1; this test needs no connections.
        self.add_nodes(self.num_nodes, self.extra_args)
        for node in self.nodes:
            node.has_explicit_bind = True
        self.start_nodes()


if __name__ == '__main__':
    Copy(__file__).main()
