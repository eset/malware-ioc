# -*- encoding: utf-8 -*-

# Copyright (c) 2016, ESET
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Author: Peter Kalnai <peter.kalnai@eset.cz>
# Date: 2016-12-20
# Version: 1.0
#
# Volatility Framework plugin to detect the Linux/Rakos.A malware and dump its
# configuration from memory.
#
# Usage:
# 1) Move vf_ioc_linux_rakos.py to volatility/plugins/malware in the
#    Volatilty Framework path.
# 2) Run: python vol.py -f dump_from_compromise_linux_system.vmem
#    --profile=LinuxUbuntu_14_04_krn_4_2_AMDx64 vf_ioc_linux_rakos


from volatility import utils, debug
from volatility.plugins.malware import malfind
import volatility.plugins.linux.common as linux_common
from volatility.plugins.linux.banner import linux_banner
from volatility.plugins.linux.cpuinfo import linux_cpuinfo
from volatility.plugins.linux.pslist import linux_pslist
import re, socket
from volatility.plugins.linux.linux_yarascan import VmaYaraScanner

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

LINUX_RAKOS_A_RULE = {
    'namespace1' : '''rule LinuxRakosA {
                        strings:
                          $ = "upgrade/vars.yaml"
                          $ = "MUTTER"
                          $ = "/tmp/.javaxxx"
                          $ = "uckmydi"
                        condition: 3 of them }'''
}

LINUX_RAKOS_A_CONF = [
    [
        'LinuxRakosA_config',
        '---\x0A\x0Aversion(.+?)skaro(.+?)\x0A\x0Asmtp(.+?)\x0A\x00\x00\x00\x00',
        1
    ], [
        'LinuxRakosA_ping',
        '\x7B\x22arch(.+?)stats(.+?)facts(.+?)load(.+?)version\x22\x3A(\d{3})\x7D',
        0
    ],
]

LINUX_RAKOS_A_FILTER = [ ['netstat', '127.0.0.1', '61314'] ]


class linux_rakos(malfind.YaraScan):
    "Find indicators of compromise for: Linux/Rakos.A"

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'linux'

    def filter_tasks(self):
        tasks = linux_pslist(self._config).calculate()
        tasks_filt = []
        for task in tasks:
            for c_plug, c_param1, c_param2 in LINUX_RAKOS_A_FILTER: 
                if c_plug == 'netstat':
                    for ents in task.netstat():
                        if ents[0] == socket.AF_INET:
                            (_, proto, saddr, sport, daddr, dport, state) = ents[1]
                            if (str(saddr) == c_param1) and (str(sport) == c_param2):
                                tasks_filt.append(task)
                                print("Suspected PID: {0:8s} {1:<16}:{2:>5} {3:<16}:{4:>5} {5:<15s} {6:>17s}/{7:<5d}\n".format(proto, saddr, sport, daddr, dport, state, task.comm, task.pid))

        return tasks_filt

    def calculate(self):

        ## we need this module imported
        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")

        ## leveraged from the windows yarascan plugin
        rules = yara.compile(sources = LINUX_RAKOS_A_RULE)

        ## set the linux plugin address spaces 
        linux_common.set_plugin_members(self)

        tasks = self.filter_tasks()
        for task in tasks: 
            scanner = VmaYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():
               yield (task, address, hit, scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE))
               break

    def render_text(self, outfd, data):

        banners = linux_banner(self._config).calculate()
        for banner in banners:
            outfd.write("Memory dump from:\n {0:s}\n\n".format(banner))
        cpus = linux_cpuinfo(self._config).calculate()
        for idx, vendor_id, model_id in cpus:
            outfd.write("Processor {0}: {1:s} {2:s}\n\n".format(idx, vendor_id, model_id))

        for task, address, hit, buf in data:
            if task:
                outfd.write("Task {0}/{1} confirmed for hitting the rule {2} at the address {3:#x}\n".format( task.comm, task.pid, hit.rule, address))
                for vma in task.get_proc_maps():
                    proc_addr_space = task.get_process_address_space()
                    datax = proc_addr_space.zread(vma.vm_start, vma.vm_end - vma.vm_start)
                    for c_name, c_pt, c_all in LINUX_RAKOS_A_CONF:
                        if c_all == 1:
                            prog = re.compile(c_pt, re.DOTALL)
                        else:
                            prog = re.compile(c_pt)
                        for m_conf in prog.finditer(datax):
                            buf = proc_addr_space.zread(vma.vm_start + m_conf.start() , m_conf.end() - m_conf.start())

                            fname = "{0:s}_{1:s}_{2:d}_0x{3:x}.dat".format(c_name, task.comm, task.pid, vma.vm_start + m_conf.start())
                            outfd.write("Found and writing to the file {0}".format(fname))
                            with open(fname, 'wb') as f:
                                f.write(buf)
                            f.close()
