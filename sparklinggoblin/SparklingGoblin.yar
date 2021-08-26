// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2021, ESET
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
rule SparklingGoblin_ChaCha20Loader_RichHeader
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "Rule matching ChaCha20 loaders rich header"
        date = "2021-03-30"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "09FFE37A54BC4EBEBD8D56098E4C76232F35D821"
        hash = "29B147B76BB0D9E09F7297487CB972E6A2905586"
        hash = "33F2C3DE2457B758FC5824A2B253AD7C7C2E9E37"
        hash = "45BEF297CE78521EAC6EE39E7603E18360E67C5A"
        hash = "4CEC7CDC78D95C70555A153963064F216DAE8799"
        hash = "4D4C1A062A0390B20732BA4D65317827F2339B80"
        hash = "4F6949A4906B834E83FF951E135E0850FE49D5E4"

    condition:
        pe.rich_signature.length >= 104 and pe.rich_signature.length <= 112 and
        pe.rich_signature.toolid(241, 40116) >= 5 and pe.rich_signature.toolid(241, 40116) <= 10  and
        pe.rich_signature.toolid(147, 30729) == 11 and
        pe.rich_signature.toolid(264, 24215) >= 15 and pe.rich_signature.toolid(264, 24215) <= 16 
}

rule SparklingGoblin_ChaCha20
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin ChaCha20 implementations"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"
        hash = "91B32E030A1F286E7D502CA17E107D4BFBD7394A"

    strings:
        // 32-bits version
        $chunk_1 = {
            8B 4D ??
            56
            8B 75 ??
            57
            8B 7D ??
            8B 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 10
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 0C
            89 04 BB
            01 04 93
            8B 04 B3
            33 04 93
            C1 C0 08
            89 04 B3
            01 04 8B
            8B 04 BB
            33 04 8B
            C1 C0 07
            89 04 BB
        }
        // 64-bits version
        $chunk_2 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            45 33 D8
            C1 C6 10
            44 33 F2
            41 C1 C3 10
            41 03 FB
            41 C1 C6 10
            45 03 E6
            41 03 DA
            44 33 CB
            44 03 EE
            41 C1 C1 10
            8B C7
            33 45 ??
            45 03 F9
            C1 C0 0C
            44 03 C0
            45 33 D8
            44 89 45 ??
            41 C1 C3 08
            41 03 FB
            44 8B C7
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            41 33 C2
            C1 C2 07
            C1 C0 0C
            03 D8
            44 33 CB
            41 C1 C1 08
            45 03 F9
            45 8B D7
            44 33 D0
            8B 45 ??
            03 C1
            41 C1 C2 07
            44 33 C8
            89 45 ??
            41 C1 C1 10
            45 03 E1
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 C9
            89 4D ??
            89 4D ??
            41 C1 C1 08
            45 03 E1
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            41 03 D8
            89 45 ??
            41 33 C3
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
        }
        $chunk_3 = {
            C7 45 ?? 65 78 70 61
            4C 8D 45 ??
            C7 45 ?? 6E 64 20 33
            4D 8B F9
            C7 45 ?? 32 2D 62 79
            4C 2B C1
            C7 45 ?? 74 65 20 6B
        }
        $chunk_4 = {
            0F B6 02
            0F B6 4A ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            0F B6 42 ??
            C1 E1 08
            0B C8
            41 89 0C 10
            48 8D 52 ??
            49 83 E9 01
        }
        // 64-bits version
        $chunk_5 = {
            03 4D ??
            44 03 C0
            03 55 ??
            33 F1
            41 33 F8
            C1 C6 10
            44 33 F2
            C1 C7 10
            44 03 DF
            41 C1 C6 10
            45 03 E6
            44 03 CB
            45 33 D1
            44 03 EE
            41 C1 C2 10
            41 8B C3
            33 45 ??
            45 03 FA
            C1 C0 0C
            44 03 C0
            41 33 F8
            44 89 45 ??
            C1 C7 08
            44 03 DF
            45 8B C3
            44 33 C0
            41 8B C5
            33 45 ??
            C1 C0 0C
            03 C8
            41 C1 C0 07
            33 F1
            89 4D ??
            C1 C6 08
            44 03 EE
            41 8B CD
            33 C8
            41 8B C4
            33 45 ??
            C1 C0 0C
            03 D0
            C1 C1 07
            44 33 F2
            89 55 ??
            41 C1 C6 08
            45 03 E6
            41 8B D4
            33 D0
            41 8B C7
            33 C3
            C1 C2 07
            C1 C0 0C
            44 03 C8
            45 33 D1
            41 C1 C2 08
            45 03 FA
            41 8B DF
            33 D8
            8B 45 ??
            03 C1
            C1 C3 07
            44 33 D0
            89 45 ??
            41 C1 C2 10
            45 03 E2
            41 8B C4
            33 C1
            8B 4D ??
            C1 C0 0C
            03 C8
            44 33 D1
            89 4D ??
            89 4D ??
            41 C1 C2 08
            45 03 E2
            41 8B CC
            33 C8
            8B 45 ??
            C1 C1 07
            89 4D ??
            89 4D ??
            03 C2
            45 03 C8
            89 45 ??
            33 C7
            C1 C0 10
            44 03 F8
            41 8B CF
            33 CA
            8B 55 ??
            C1 C1 0C
            03 D1
            8B FA
            89 55 ??
            33 F8
            89 55 ??
            8B 55 ??
            03 D3
            C1 C7 08
            44 03 FF
            41 8B C7
            33 C1
            C1 C0 07
            89 45 ??
            89 45 ??
            8B C2
            33 C6
            C1 C0 10
            44 03 D8
            41 33 DB
            C1 C3 0C
            03 D3
            8B F2
            89 55 ??
            33 F0
            41 8B C1
            41 33 C6
            C1 C6 08
            C1 C0 10
            44 03 DE
            44 03 E8
            41 33 DB
            41 8B CD
            C1 C3 07
            41 33 C8
            44 8B 45 ??
            C1 C1 0C
            44 03 C9
            45 8B F1
            44 33 F0
            41 C1 C6 08
            45 03 EE
            41 8B C5
            33 C1
            8B 4D ??
            C1 C0 07
        }

    condition:
        any of them and filesize < 450KB

}

rule SparklingGoblin_EtwEventWrite
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin EtwEventWrite patching"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

    strings:
        // 64-bits version
        $chunk_1 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
            83 64 24 ?? 00
            4C 8D 4C 24 ??
            BF 04 00 00 00
            48 8B C8
            8B D7
            48 8B D8
            44 8D 47 ??
            FF 15 ?? ?? ?? ??
            44 8B C7
            48 8D 54 24 ??
            48 8B CB
            E8 ?? ?? ?? ??
            44 8B 44 24 ??
            4C 8D 4C 24 ??
            8B D7
            48 8B CB
            FF 15 ?? ?? ?? ??
            48 8B 05 ?? ?? ?? ??
        }
        // 32-bits version
        $chunk_2 = {
            55
            8B EC
            51
            51
            57
            68 08 1A 41 00
            66 C7 45 ?? C2 14
            C6 45 ?? 00
            FF 15 ?? ?? ?? ??
            68 10 1A 41 00
            50
            FF 15 ?? ?? ?? ??
            83 65 ?? 00
            8B F8
            8D 45 ??
            50
            6A 40
            6A 03
            57
            FF 15 ?? ?? ?? ??
            6A 03
            8D 45 ??
            50
            57
            E8 ?? ?? ?? ??
            83 C4 0C
            8D 45 ??
            50
            FF 75 ??
            6A 03
            57
            FF 15 ?? ?? ?? ??
        }
        // 64-bits version
        $chunk_3 = {
            48 8D 0D ?? ?? ?? ??
            C7 44 24 ?? 48 31 C0 C3
            FF 15 ?? ?? ?? ??
            48 8B C8
            48 8D 15 ?? ?? ?? ??
            FF 15 ?? ?? ?? ??
        }

    condition:
        any of them
}

rule SparklingGoblin_Mutex
{
    meta:
        author = "ESET Research"
        copyright = "ESET Research"
        description = "SparklingGoblin ChaCha20 loaders mutexes"
        date = "2021-05-20"
        reference = "http://welivesecurity.com/2021/08/24/sidewalk-may-be-as-dangerous-as-crosswalk/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"

        hash = "2EDBEA43F5C40C867E5B6BBD93CC972525DF598B"
        hash = "B6D245D3D49B06645C0578804064CE0C072CBE0F"
        hash = "8BE6D5F040D0085C62B1459AFC627707B0DE89CF"
        hash = "4668302969FE122874FB2447A80378DCB671C86B"
        hash = "9BDECB08E16A23D271D0A3E836D9E7F83D7E2C3B"
        hash = "9CE7650F2C08C391A35D69956E171932D116B8BD"

    strings:
        $mutex_1 = "kREwdFrOlvASgP4zWZyV89m6T2K0bIno"
        $mutex_2 = "v5EPQFOImpTLaGZes3Nl1JSKHku8AyCw"

    condition:
        any of them
}
