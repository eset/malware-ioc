// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
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

private rule InvisiMole_Blob {
    meta:
        description = "Detects InvisiMole blobs by magic values"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $magic_old_32 = {F9 FF D0 DE}
        $magic_old_64 = {64 FF D0 DE}
        $magic_new_32 = {86 DA 11 CE}
        $magic_new_64 = {64 DA 11 CE}

    condition:
        ($magic_old_32 at 0) or ($magic_old_64 at 0) or ($magic_new_32 at 0) or ($magic_new_64 at 0)
}

rule apt_Windows_InvisiMole_Logs {
    meta:
        description = "Detects log files with collected created by InvisiMole's RC2CL backdoor"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    condition:
        uint32(0) == 0x08F1CAA1 or
        uint32(0) == 0x08F1CAA2 or
        uint32(0) == 0x08F1CCC0 or
        uint32(0) == 0x08F2AFC0 or
        uint32(0) == 0x083AE4DF or
        uint32(0) == 0x18F2CBB1 or
        uint32(0) == 0x1900ABBA or
        uint32(0) == 0x24F2CEA1 or
        uint32(0) == 0xDA012193 or
        uint32(0) == 0xDA018993 or
        uint32(0) == 0xDA018995 or
        uint32(0) == 0xDD018991
}

rule apt_Windows_InvisiMole_SFX_Dropper {

    meta:
        description = "Detects trojanized InvisiMole files: patched RAR SFX droppers with added InvisiMole blobs (config encrypted XOR 2A at the end of a file)"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $encrypted_config = {5F 59 4F 58 19 18 04 4E 46 46 2A 5D 59 5A 58 43 44 5E 4C 7D 2A 0F 2A 59 2A 78 2A 4B 2A 58 2A 0E 2A 6F 2A 72 2A 4B 2A 0F 2A 4E 2A 04 2A 0F 2A 4E 2A 76 2A 0F 2A 79 2A 2A 2A 79 42 4F 46 46 6F 52 4F 49 5F 5E 4F 7D 2A 79 42 4F 46 46 19 18 04 4E 46 46 2A 7C 43 58 5E 5F 4B 46 6B 46 46 45 49 2A 66 45 4B 4E 66 43 48 58 4B 58 53 6B}

    condition:
        uint16(0) == 0x5A4D and $encrypted_config
}

rule apt_Windows_InvisiMole_CPL_Loader {
    meta:
        description = "CPL loader"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "WScr%steObject(\"WScr%s.Run(\"::{20d04fe0-3a%s30309d}\\\\::{21EC%sDD-08002B3030%s\", 0);"
        $s2 = "\\Control.js" wide
        $s3 = "\\Control Panel.lnk" wide
        $s4 = "FPC 3.0.4 [2019/04/13] for x86_64 - Win64"
        $s5 = "FPC 3.0.4 [2019/04/13] for i386 - Win32"
        $s6 = "imageapplet.dat" wide
        $s7 = "wkssvmtx"

    condition:
        uint16(0) == 0x5A4D and (3 of them)
}

rule apt_Windows_InvisiMole_Wrapper_DLL {
    meta:
        description = "Detects InvisiMole wrapper DLL with embedded RC2CL and RC2FM backdoors, by export and resource names"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/2018/06/07/invisimole-equipped-spyware-undercover/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    condition:
        pe.exports("GetDataLength") and
        for any y in (0..pe.number_of_resources - 1): (
            pe.resources[y].type == pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string == "R\x00C\x002\x00C\x00L\x00"
        ) and
        for any y in (0..pe.number_of_resources - 1): (
            pe.resources[y].type == pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string == "R\x00C\x002\x00F\x00M\x00"
        )
}

rule apt_Windows_InvisiMole_DNS_Downloader {

    meta:
        description = "InvisiMole DNS downloader"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $d = "DnsQuery_A"

        $s1 = "Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}" xor
        $s2 = "AddIns\\" ascii wide xor
        $s3 = "pcornomeex." xor
        $s4 = "weriahsek.rxe" xor
        $s5 = "dpmupaceex." xor
        $s6 = "TCPViewClass" xor
        $s7 = "PROCMON_WINDOW_CLASS" xor
        $s8 = "Key%C"
        $s9 = "AutoEx%C" xor
        $s10 = "MSO~"
        $s11 = "MDE~"
        $s12 = "DNS PLUGIN, Step %d" xor
        $s13 = "rundll32.exe \"%s\",StartUI"

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and $d and 5 of ($s*)
}

rule apt_Windows_InvisiMole_RC2CL_Backdoor {

    meta:
        description = "InvisiMole RC2CL backdoor"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "RC2CL" wide

        $s2 = "hp12KsNh92Dwd" wide
        $s3 = "ZLib package %s: files: %d, total size: %d" wide
        $s4 = "\\Un4seen" wide
        $s5 = {9E 01 3A AD} // encryption key

        $s6 = "~mrc_" wide
        $s7 = "~src_" wide
        $s8 = "~wbc_" wide
        $s9 = "zdf_" wide
        $s10 = "~S0PM" wide
        $s11 = "~A0FM" wide
        $s12 = "~70Z63\\" wide
        $s13 = "~E070C" wide
        $s14 = "~N031E" wide

        $s15 = "%szdf_%s.data" wide
        $s16 = "%spicture.crd" wide
        $s17 = "%s70zf_%s.cab" wide
        $s18 = "%spreview.crd" wide

        $s19 = "Value_Bck" wide
        $s20 = "Value_WSFX_ZC" wide
        $s21 = "MachineAccessStateData" wide
        $s22 = "SettingsSR2" wide

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and 5 of ($s*)
}

rule apt_Windows_InvisiMole {

    meta:
        description = "InvisiMole magic values, keys and strings"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "CryptProtectData"
        $s2 = "CryptUnprotectData"
        $s3 = {9E 01 3A AD}
        $s4 = "GET /getversion2a/%d%.2X%.2X/U%sN HTTP/1.1"
        $s5 = "PULSAR_LOADER.dll"

        /*
        cmp reg, 0DED0FFF9h
        */
        $check_magic_old_32 = {3? F9 FF D0 DE}

        /*
        cmp reg, 0DED0FF64h
        */
        $check_magic_old_64 = {3? 64 FF D0 DE}

        /*
        cmp dword ptr [reg], 0CE11DA86h
        */
        $check_magic_new_32 = {81 3? 86 DA 11 CE}

        /*
        cmp dword ptr [reg], 0CE11DA64h
        */
        $check_magic_new_64 = {81 3? 64 DA 11 CE}

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and (any of ($check_magic*)) and (2 of ($s*))
}

rule apt_Windows_InvisiMole_C2 {

    meta:
        description = "InvisiMole C&C servers"
        author = "ESET Research"
        date = "2021-05-17"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "46.165.220.228" ascii wide
        $s2 = "80.255.3.66" ascii wide
        $s3 = "85.17.26.174" ascii wide
        $s4 = "185.193.38.55" ascii wide
        $s5 = "194.187.249.157"  ascii wide
        $s6 = "195.154.255.211"  ascii wide
        $s7 = "153.re"  ascii wide fullword
        $s8 = "adstat.red"  ascii wide
        $s9 = "adtrax.net"  ascii wide
        $s10 = "akamai.sytes.net"  ascii wide
        $s11 = "amz-eu401.com"  ascii wide
        $s12 = "blabla234342.sytes.net"  ascii wide
        $s13 = "mx1.be"  ascii wide fullword
        $s14 = "statad.de"  ascii wide
        $s15 = "time.servehttp.com"  ascii wide
        $s16 = "upd.re"  ascii wide fullword
        $s17 = "update.xn--6frz82g"  ascii wide
        $s18 = "updatecloud.sytes.net"  ascii wide
        $s19 = "updchecking.sytes.net"  ascii wide
        $s20 = "wlsts.net"  ascii wide
        $s21 = "ro2.host"  ascii wide fullword
        $s22 = "2ld.xyz"  ascii wide fullword
        $s23 = "the-haba.com"  ascii wide
        $s24 = "82.202.172.134"  ascii wide
        $s25 = "update.xn--6frz82g"  ascii wide

    condition:
        ((uint16(0) == 0x5A4D) or InvisiMole_Blob) and $s21 and any of them
}
