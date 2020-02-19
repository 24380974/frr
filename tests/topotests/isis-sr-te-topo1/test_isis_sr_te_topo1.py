#!/usr/bin/env python

#
# test_isis_sr_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_isis_sr_te_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
"""

import os
import sys
import pytest
import json
import re
from time import sleep
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

class TemplateTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        #
        # Define FRR Routers
        #
        for router in ['rt1', 'rt2', 'rt3', 'rt4', 'rt5', 'rt6']:
            tgen.add_router(router)

        #
        # Define connections
        #
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['rt1'], nodeif="eth-sw1")
        switch.add_link(tgen.gears['rt2'], nodeif="eth-sw1")
        switch.add_link(tgen.gears['rt3'], nodeif="eth-sw1")

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['rt2'], nodeif="eth-rt4-1")
        switch.add_link(tgen.gears['rt4'], nodeif="eth-rt2-1")

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['rt2'], nodeif="eth-rt4-2")
        switch.add_link(tgen.gears['rt4'], nodeif="eth-rt2-2")

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['rt3'], nodeif="eth-rt5-1")
        switch.add_link(tgen.gears['rt5'], nodeif="eth-rt3-1")

        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['rt3'], nodeif="eth-rt5-2")
        switch.add_link(tgen.gears['rt5'], nodeif="eth-rt3-2")

        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['rt4'], nodeif="eth-rt5")
        switch.add_link(tgen.gears['rt5'], nodeif="eth-rt4")

        switch = tgen.add_switch('s7')
        switch.add_link(tgen.gears['rt4'], nodeif="eth-rt6")
        switch.add_link(tgen.gears['rt6'], nodeif="eth-rt4")

        switch = tgen.add_switch('s8')
        switch.add_link(tgen.gears['rt5'], nodeif="eth-rt6")
        switch.add_link(tgen.gears['rt6'], nodeif="eth-rt5")

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS,
            os.path.join(CWD, '{}/isisd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH,
            os.path.join(CWD, '{}/pathd.conf'.format(rname))
        )

    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = '{}/{}/{}'.format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp,
        tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg

#
# Step 1
#
def test_srte_config_step1():
    logger.info("Test (step 1): SR-TE config")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['rt1', 'rt6']:
        router_compare_json_output(rname,
                                   "show yang operational-data /frr-pathd:pathd pathd",
                                   "step1/show_operational_data.ref")

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
