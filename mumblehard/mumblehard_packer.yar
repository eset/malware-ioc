// Mumblehard packer yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
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

rule mumblehard_packer
{
    meta:
        description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
        author = "Marc-Etienne M.Léveillé"
        date = "2015-04-07"
        reference = "http://www.welivesecurity.com"
        version = "1"

    strings:
        $decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-6]  (56 5f |  89 F7)
                     39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
                     00 31 db 43 ac 30 d8 aa 43 e2 e2 }
    condition:
        $decrypt
}