# This Kaitai Struct is provided to the community under the two-clause BSD
# license as follows:
#
# Copyright (c) 2018, ESET
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
#

meta:
  id: kessel_config
  title: Kessel OpenSSH backdoor configuration blob
  license: BSD 2-Clause
  endian: le
doc-ref: 'https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf'
seq:
  - id: host
    type: str
    size: 100
    encoding: UTF-8
  - id: port
    type: u4
  - id: timeout
    type: u4
  - id: dns_enable
    type: u4
  - id: dns_report_enable
    type: u4
  - id: dns_ip
    type: str
    size: 100
    encoding: UTF-8
  - id: dns_port
    type: u4
  - id: dns_sub_host
    type: str
    size: 100
    encoding: UTF-8
  - id: socks_proxy_enable
    type: u4
  - id: socks_proxy_host
    type: str
    size: 100
    encoding: UTF-8
  - id: socks_proxy_port
    type: u4
  - id: http_proxy_enable
    type: u4
  - id: http_proxy_host
    type: str
    size: 100
    encoding: UTF-8
  - id: http_proxy_port
    type: u4
  - id: custom_protocol_enable
    type: u4
  - id: bc_local_host
    type: str
    size: 100
    encoding: UTF-8
  - id: bc_local_port
    type: u4
  - id: http_enable
    type: u4
  - id: http_port
    type: u4
  - id: http_fake_host
    type: str
    size: 100
    encoding: UTF-8
  - id: log_enable
    type: u4
  - id: log_file
    type: str
    size: 256
    encoding: UTF-8
  - id: masterpass
    type: str
    size: 100
    encoding: UTF-8
  - id: masterkey
    type: str
    size: 512
    encoding: UTF-8
