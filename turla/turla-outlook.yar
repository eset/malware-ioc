// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2018, ESET
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

private rule not_ms {
    condition:
        not for any i in (0..pe.number_of_signatures - 1):
        (
            pe.signatures[i].issuer contains "Microsoft Corporation"
        )
}

rule turla_outlook_gen {
    meta:
        author      = "ESET Research"
        date        = "05-09-2018"
        description = "Turla Outlook malware"
        version     = 2
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"    
    strings:
        $s1 = "Outlook Express" ascii wide
        $s2 = "Outlook watchdog" ascii wide
        $s3 = "Software\\RIT\\The Bat!" ascii wide
        $s4 = "Mail Event Window" ascii wide
        $s5 = "Software\\Mozilla\\Mozilla Thunderbird\\Profiles" ascii wide
        $s6 = "%%PDF-1.4\n%%%c%c\n" ascii wide
        $s7 = "%Y-%m-%dT%H:%M:%S+0000" ascii wide
        $s8 = "rctrl_renwnd32" ascii wide
        $s9 = "NetUIHWND" ascii wide
        $s10 = "homePostalAddress" ascii wide
        $s11 = "/EXPORT;OVERRIDE;START=-%d;END=-%d;FOLDER=%s;OUT=" ascii wide
        $s12 = "Re:|FWD:|AW:|FYI:|NT|QUE:" ascii wide
        $s13 = "IPM.Note" ascii wide
        $s14 = "MAPILogonEx" ascii wide
        $s15 = "pipe\\The Bat! %d CmdLine" ascii wide
        $s16 = "PowerShellRunner.dll" ascii wide
        $s17 = "cmd container" ascii wide
        $s18 = "mapid.tlb" ascii wide nocase
        $s19 = "Content-Type: F)*+" ascii wide fullword
    condition:
        not_ms and 5 of them
}

rule turla_outlook_filenames {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Turla Outlook filenames"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"   
    strings:
        $s1 = "mapid.tlb"
        $s2 = "msmime.dll"
        $s3 = "scawrdot.db"
    condition:
        any of them
}

rule turla_outlook_log {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "First bytes of the encrypted Turla Outlook logs"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"   
    strings:
        //Log begin: [...] TVer
        $s1 = {01 87 C9 75 C8 69 98 AC E0 C9 7B [21] EB BB 60 BB 5A}
    condition:
        $s1 at 0
}

rule turla_outlook_exports {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Export names of Turla Outlook Malware"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    condition:
        (pe.exports("install") or pe.exports("Install")) and
        pe.exports("TBP_Initialize") and
        pe.exports("TBP_Finalize") and
        pe.exports("TBP_GetName") and
        pe.exports("DllRegisterServer") and
        pe.exports("DllGetClassObject")
}

rule turla_outlook_pdf {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Detect PDF documents generated by Turla Outlook malware"
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    strings:
        $s1 = "Adobe PDF Library 9.0" ascii wide nocase
        $s2 = "Acrobat PDFMaker 9.0"  ascii wide nocase
        $s3 = {FF D8 FF E0 00 10 4A 46 49 46}
        $s4 = {00 3F 00 FD FC A2 8A 28 03 FF D9}
        $s5 = "W5M0MpCehiHzreSzNTczkc9d" ascii wide nocase
        $s6 = "PDF-1.4" ascii wide nocase
    condition:
        5 of them
}

rule outlook_misty1 {
    meta:
        author      = "ESET Research"
        date        = "22-08-2018"
        description = "Detects the Turla MISTY1 implementation"             
        reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"
        source = "https://github.com/eset/malware-ioc/"
        contact = "github@eset.com"
        license = "BSD 2-Clause"  
    strings:
        //and     edi, 1FFh
        $o1 = {81 E7 FF 01 00 00}
        //shl     ecx, 9
        $s1 = {C1 E1 09}
        //xor     ax, si
        $s2 = {66 33 C6}
        //shr     eax, 7
        $s3 = {C1 E8 07}
        $o2 = {8B 11 8D 04 1F 50 03 D3 8D 4D C4}
    condition:
        $o2 and for all i in (1..#o1):
            (for all of ($s*) : ($ in (@o1[i] -500 ..@o1[i] + 500)))
}
