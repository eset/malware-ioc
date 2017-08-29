// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2017, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
import "pe"

rule Gazer_certificate_subject {
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

condition:
    for any i in (0..pe.number_of_signatures - 1):
        (pe.signatures[i].subject contains "Solid Loop" or pe.signatures[i].subject contains "Ultimate Computer Support")
}

rule Gazer_certificate
{
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $certif1 = {52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02}
    $certif2 = {12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c}

  condition:
    (uint16(0) == 0x5a4d) and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name
{
  meta:
    author      = "ESET Research"
    date        = "2017-08-30"
    description = "Turla Gazer malware"
    reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $s1 = "CVRG72B5.tmp.cvr"
    $s2 = "CVRG1A6B.tmp.cvr"
    $s3 = "CVRG38D9.tmp.cvr"

  condition:
    (uint16(0) == 0x5a4d) and 1 of them
}
