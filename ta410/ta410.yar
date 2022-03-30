// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2022, ESET
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

rule apt_Windows_TA410_Tendyron_dropper
{
    meta:
        description = "TA410 Tendyron Dropper"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        $s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
        $s2 = "Global\\8D32CCB321B2" wide
        $s3 = "Global\\E4FE94F75490" wide
        $s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
        $s5 = "\\RPC Control\\OLE" wide
        $s6 = "ALPC Port" wide
    condition:
        int16(0) == 0x5A4D and 4 of them
}

rule apt_Windows_TA410_Tendyron_installer
{
    meta:
        description = "TA410 Tendyron Installer"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        $s1 = "Tendyron" wide
        $s2 = "OnKeyToken_KEB.dll" wide
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s4 = "Global\\8D32CCB321B2"
        $s5 = "\\RTFExploit\\"
    condition:
        int16(0) == 0x5A4D and 3 of them
}

rule apt_Windows_TA410_Tendyron_Downloader
{
    meta:
        description = "TA410 Tendyron Downloader"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        /*
        0x401250 8A10                          mov dl, byte ptr [eax]
        0x401252 80F25C                        xor dl, 0x5c
        0x401255 80C25C                        add dl, 0x5c
        0x401258 8810                          mov byte ptr [eax], dl
        0x40125a 40                            inc eax
        0x40125b 83E901                        sub ecx, 1
        0x40125e 75F0                          jne 0x401250
         */
        $chunk_1 = {
            8A 10
            80 F2 5C
            80 C2 5C
            88 10
            40
            83 E9 01
            75 ??
        }
        $s1 = "startModule" fullword
    condition:
        int16(0) == 0x5A4D and all of them
}

rule apt_Windows_TA410_X4_strings
{
    meta:
        description = "Matches various strings found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"
    strings:
        $s1 = "[X]InLoadSC" ascii wide nocase
        $s3 = "MachineKeys\\Log\\rsa.txt" ascii wide nocase
        $s4 = "MachineKeys\\Log\\output.log" ascii wide nocase
    condition:
        any of them
}

rule apt_Windows_TA410_X4_hash_values
{
    meta:
        description = "Matches X4 hash function found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"
    strings:
        $s1 = {D1 10 76 C2 B6 03}
        $s2 = {71 3E A8 0D}
        $s3 = {DC 78 94 0E}
        $s4 = {40 0D E7 D6 06}
        $s5 = {83 BB FD E8 06}
        $s6 = {92 9D 9B FF EC 03}
        $s7 = {DD 0E FC FA F5 03}
        $s8 = {15 60 1E FB F5 03}
    condition:
        uint16(0) == 0x5a4d and 4 of them

}

rule apt_Windows_TA410_X4_hash_fct
{
    meta:
        description = "Matches X4 hash function found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"

    /*
    0x6056cc2150 0FB601                        movzx eax, byte ptr [rcx]
    0x6056cc2153 84C0                          test al, al
    0x6056cc2155 7416                          je 0x6056cc216d
    0x6056cc2157 4869D283000000                imul rdx, rdx, 0x83
    0x6056cc215e 480FBEC0                      movsx rax, al
    0x6056cc2162 4803D0                        add rdx, rax
    0x6056cc2165 48FFC1                        inc rcx
    0x6056cc2168 E9E3FFFFFF                    jmp 0x6056cc2150
     */
    strings:
        $chunk_1 = {
            0F B6 01
            84 C0
            74 ??
            48 69 D2 83 00 00 00
            48 0F BE C0
            48 03 D0
            48 FF C1
            E9 ?? ?? ?? ??
        }

    condition:
        uint16(0) == 0x5a4d and any of them

}

rule apt_Windows_TA410_LookBack_decryption
{
    meta:
        description = "Matches encryption/decryption function used by LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
        }
        $generate = {
            8A 94 1C 10 01 ?? ??    //mov dl, byte ptr [esp + ebx + 0x110]
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            0F B6 C3        //movzx eax, bl
            0F B6 44 04 10      //movzx eax, byte ptr [esp + eax + 0x10]
            32 C2           //xor al, dl
            02 F0           //add dh, al
            0F B6 C6        //movzx eax, dh
            03 C8           //add ecx, eax
            0F B6 01        //movzx eax, byte ptr [ecx]
            88 84 1C 10 01 ?? ??    //mov byte ptr [esp + ebx + 0x110], al
            43              //inc ebx
            88 11           //mov byte ptr [ecx], dl
            81 FB 00 06 00 00       //cmp ebx, 0x600
            72 ??           //jb 0x10025930
        }
        $decrypt = {
            0F B6 C6        //movzx eax, dh
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            03 C8           //add ecx, eax
            8A 19           //mov bl, byte ptr [ecx]
            8A C3           //mov al, bl
            02 C6           //add al, dh
            FE C6           //inc dh
            02 F8           //add bh, al
            0F B6 C7        //movzx eax, bh
            8A 94 04 10 01 ?? ??    //mov dl, byte ptr [esp + eax + 0x110]
            88 9C 04 10 01 ?? ??    //mov byte ptr [esp + eax + 0x110], bl
            88 11           //mov byte ptr [ecx], dl
            0F B6 C2        //movzx eax, dl
            0F B6 CB        //movzx ecx, bl
            33 C8           //xor ecx, eax
            8A 84 0C 10 01 ?? ??    //mov al, byte ptr [esp + ecx + 0x110]
            30 04 2E        //xor byte ptr [esi + ebp], al
            46              //inc esi
            3B F7           //cmp esi, edi
            7C ??           //jl 0x10025980
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_loader
{
    meta:
        description = "Matches the modified function in LookBack libcurl loader."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $chunk_1 = {
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530e0]
            6A 40          //push 0x40
            68 00 10 00 00     //push 0x1000
            68 F0 04 00 00     //push 0x4f0
            6A 00          //push 0
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530d4]
            8B E8          //mov ebp, eax
            B9 3C 01 00 00     //mov ecx, 0x13c
            BE 60 30 06 10     //mov esi, 0x10063060
            8B FD          //mov edi, ebp
            68 F0 04 00 00     //push 0x4f0
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            55             //push ebp
            E8 ?? ?? ?? ??     //call 0x100258d0
            8B 0D ?? ?? ?? ??      //mov ecx, dword ptr [0x100530e4]
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x100530c8]
            68 6C 02 00 00     //push 0x26c
            89 4C 24 ??        //mov dword ptr [esp + 0x1c], ecx
            89 44 24 ??        //mov dword ptr [esp + 0x20], eax
            FF 15 ?? ?? ?? ??      //call dword ptr [0x10063038]
            8B D8          //mov ebx, eax
            B9 9B 00 00 00     //mov ecx, 0x9b
            BE 50 35 06 10     //mov esi, 0x10063550
            8B FB          //mov edi, ebx
            68 6C 02 00 00      //push 0x26c
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            53             //push ebx
            E8 ?? ?? ?? ??     //call 0x100258d0
            83 C4 14           //add esp, 0x14
            8D 44 24 ??        //lea eax, [esp + 0x10]
            50             //push eax
            53             //push ebx
            8D 44 24 ??        //lea eax, [esp + 0x3c]
            50             //push eax
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x10063058]
            FF 74 24 ??        //push dword ptr [esp + 0x28]
            03 C5          //add eax, ebp
            FF D0          //call eax
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_strings
{
    meta:
        description = "Matches multiple strings and export names in TA410 LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "SodomMainFree" ascii wide
        $s2 = "SodomMainInit" ascii wide
        $s3 = "SodomNormal.bin" ascii wide
        $s4 = "SodomHttp.bin" ascii wide
        $s5 = "sodom.ini" ascii wide
        $s6 = "SodomMainProc" ascii wide

    condition:
        uint16(0) == 0x5a4d and (2 of them or pe.exports("SodomBodyLoad") or pe.exports("SodomBodyLoadTest"))
}

rule apt_Windows_TA410_LookBack_HTTP
{
    meta:
        description = "Matches LookBack's hardcoded HTTP request"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "POST http://%s/status.php?r=%d%d HTTP/1.1\x0d\nAccept: text/html, application/xhtml+xml, */*\x0d\nAccept-Language: en-us\x0d\nUser-Agent: %s\x0d\nContent-Type: application/x-www-form-urlencoded\x0d\nAccept-Encoding: gzip, deflate\x0d\nHost: %s\x0d\nContent-Length: %d\x0d\nConnection: Keep-Alive\x0d\nCache-Control: no-cache\x0d\n\x0d\n" ascii wide
        $s2 = "id=1&op=report&status="

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_LookBack_magic
{
    meta:
        description = "Matches message header creation in LookBack."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = {
            C7 03 C2 2E AB 48           //mov dword ptr [ebx], 0x48ab2ec2
            ( A1 | 8B 15 ) ?? ?? ?? ??      //mov (eax | edx), x
            [0-1]               //push ebp
            89 ?3 04            //mov dword ptr [ebc + 4], reg
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            89 4? 08            //mov dword ptr [ebx + 8], ??
            89 ?? 0C            //mov dword ptr [ebx + 0xc], ??
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            [1-2]               //push 1 or 2 args
            E8 ?? ?? ?? ??          //call
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_loader_strings
{
    meta:
        description = "Matches various strings found in TA410 FlowCloud first stage."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $key = "y983nfdicu3j2dcn09wur9*^&initialize(y4r3inf;'fdskaf'SKF"
        $s2 = "startModule" fullword
        $s4 = "auto_start_module" wide
        $s5 = "load_main_module_after_install" wide
        $s6 = "terminate_if_fail" wide
        $s7 = "clear_run_mru" wide
        $s8 = "install_to_vista" wide
        $s9 = "load_ext_module" wide
        $s10= "sll_only" wide
        $s11= "fail_if_already_installed" wide
        $s12= "clear_hardware_info" wide
        $s13= "av_check" wide fullword
        $s14= "check_rs" wide
        $s15= "check_360" wide
        $s16= "responsor.dat" wide ascii
        $s17= "auto_start_after_install_check_anti" wide fullword
        $s18= "auto_start_after_install" wide fullword
        $s19= "extern_config.dat" wide fullword
        $s20= "is_hhw" wide fullword
        $s21= "SYSTEM\\Setup\\PrintResponsor" wide
        $event= "Global\\Event_{201a283f-e52b-450e-bf44-7dc436037e56}" wide ascii
        $s23= "invalid encrypto hdr while decrypting"

    condition:
        uint16(0) == 0x5a4d and ($key or $event or 5 of ($s*))
}

rule apt_Windows_TA410_FlowCloud_header_decryption
{
    meta:
        description = "Matches the function used to decrypt resources headers in TA410 FlowCloud"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
    /*
    0x416a70 8B1E              mov ebx, dword ptr [esi]
    0x416a72 8BCF              mov ecx, edi
    0x416a74 D3CB              ror ebx, cl
    0x416a76 8D0C28            lea ecx, [eax + ebp]
    0x416a79 83C706            add edi, 6
    0x416a7c 3018              xor byte ptr [eax], bl
    0x416a7e 8B1E              mov ebx, dword ptr [esi]
    0x416a80 D3CB              ror ebx, cl
    0x416a82 8D0C02            lea ecx, [edx + eax]
    0x416a85 305801            xor byte ptr [eax + 1], bl
    0x416a88 8B1E              mov ebx, dword ptr [esi]
    0x416a8a D3CB              ror ebx, cl
    0x416a8c 8B4C240C              mov ecx, dword ptr [esp + 0xc]
    0x416a90 03C8              add ecx, eax
    0x416a92 305802            xor byte ptr [eax + 2], bl
    0x416a95 8B1E              mov ebx, dword ptr [esi]
    0x416a97 D3CB              ror ebx, cl
    0x416a99 8B4C2410              mov ecx, dword ptr [esp + 0x10]
    0x416a9d 03C8              add ecx, eax
    0x416a9f 305803            xor byte ptr [eax + 3], bl
    0x416aa2 8B1E              mov ebx, dword ptr [esi]
    0x416aa4 D3CB              ror ebx, cl
    0x416aa6 8B4C2414              mov ecx, dword ptr [esp + 0x14]
    0x416aaa 03C8              add ecx, eax
    0x416aac 83C006            add eax, 6
    0x416aaf 3058FE            xor byte ptr [eax - 2], bl
    0x416ab2 8B1E              mov ebx, dword ptr [esi]
    0x416ab4 D3CB              ror ebx, cl
    0x416ab6 3058FF            xor byte ptr [eax - 1], bl
    0x416ab9 83FF10            cmp edi, 0x10
    0x416abc 72B2              jb 0x416a70
     */
    strings:
        $chunk_1 = {
            8B 1E
            8B CF
            D3 CB
            8D 0C 28
            83 C7 06
            30 18
            8B 1E
            D3 CB
            8D 0C 02
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            83 C0 06
            30 58 ??
            8B 1E
            D3 CB
            30 58 ??
            83 FF 10
            72 ??
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_dll_hijacking_strings
{
    meta:
        description = "Matches filenames inside TA410 FlowCloud malicious DLL."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $dat1 = "emedres.dat" wide
        $dat2 = "vviewres.dat" wide
        $dat3 = "setlangloc.dat" wide
        $dll1 = "emedres.dll" wide
        $dll2 = "vviewres.dll" wide
        $dll3 = "setlangloc.dll" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($dat*) or all of ($dll*))
}

rule apt_Windows_TA410_FlowCloud_malicious_dll_antianalysis
{
    meta:
        description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
    /*
        33C0              xor eax, eax
        E8320C0000            call 0x10001d30
        83C010            add eax, 0x10
        3D00000080            cmp eax, 0x80000000
        7D01              jge +3
        EBFF              jmp +1 / jmp eax
        E050              loopne 0x1000115c / push eax
        C3                ret
    */
        $chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
        }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_pdb
{
    meta:
        description = "Matches PDB paths found in TA410 FlowCloud."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"

    condition:
        uint16(0) == 0x5a4d and (pe.pdb_path contains "\\FlowCloud\\trunk\\" or pe.pdb_path contains "\\flowcloud\\trunk\\")
}

rule apt_Windows_TA410_FlowCloud_shellcode_decryption
{
    meta:
        description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    /*
    0x211 33D2              xor edx, edx
    0x213 8B4510            mov eax, dword ptr [ebp + 0x10]
    0x216 BB6B040000            mov ebx, 0x46b
    0x21b F7F3              div ebx
    0x21d 81C2A8010000          add edx, 0x1a8
    0x223 81E2FF000000          and edx, 0xff
    0x229 8B7D08            mov edi, dword ptr [ebp + 8]
    0x22c 33C9              xor ecx, ecx
    0x22e EB07              jmp 0x237
    0x230 301439            xor byte ptr [ecx + edi], dl
    0x233 001439            add byte ptr [ecx + edi], dl
    0x236 41                inc ecx
    0x237 3B4D0C            cmp ecx, dword ptr [ebp + 0xc]
    0x23a 72F4              jb 0x230
     */
    strings:
        $chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule apt_Windows_TA410_FlowCloud_fcClient_strings
{
    meta:
        description = "Strings found in fcClient/rescure.dat module."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "df257bdd-847c-490e-9ef9-1d7dc883d3c0"
        $s2 = "\\{2AFF264E-B722-4359-8E0F-947B85594A9A}"
        $s3 = "Global\\{26C96B51-2B5D-4D7B-BED1-3DCA4848EDD1}" wide
        $s4 = "{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" wide
        $s5 = "{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" wide
        $s6 = "XXXModule_func.dll"
        $driver1 = "\\drivers\\hidmouse.sys" wide fullword
        $driver2 = "\\drivers\\hidusb.sys" wide fullword

    condition:
        uint16(0) == 0x5a4d and (any of ($s*) or all of ($driver*))
}

rule apt_Windows_TA410_FlowCloud_fcClientDll_strings
{
    meta:
        description = "Strings found in fcClientDll/responsor.dat module."
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $s1 = "http://%s/html/portlet/ext/draco/resources/draco_manager.swf/[[DYNAMIC]]/1"
        $s2 = "Cookie: COOKIE_SUPPORT=true; JSESSIONID=5C7E7A60D01D2891F40648DAB6CB3DF4.jvm1; COMPANY_ID=10301; ID=666e7375545678695645673d; PASSWORD=7a4b48574d746470447a303d; LOGIN=6863303130; SCREEN_NAME=4a2b455377766b657451493d; GUEST_LANGUAGE_ID=en-US"
        $fc_msg = ".fc_net.msg"
        $s4 = "\\pipe\\namedpipe_keymousespy_english" wide
        $s5 = "8932910381748^&*^$58876$%^ghjfgsa413901280dfjslajflsdka&*(^7867=89^&*F(^&*5678f5ds765f76%&*%&*5"
        $s6 = "cls_{CACB140B-0B82-4340-9B05-7983017BA3A4}" wide
        $s7 = "HTTP/1.1 200 OK\x0d\nServer: Apache-Coyote/1.1\x0d\nPragma: No-cache\x0d\nCache-Control: no-cache\x0d\nExpires: Thu, 01 Jan 1970 08:00:00 CST\x0d\nLast-Modified: Fri, 27 Apr 2012 08:11:04 GMT\x0d\nContent-Type: application/xml\x0d\nContent-Length: %d\x0d\nDate: %s GMT"
        $sql1 = "create table if not exists table_filed_space"
        $sql2 = "create table if not exists clipboard"
        $sql3 = "create trigger if not exists file_after_delete after delete on file"
        $sql4 = "create trigger if not exists file_data_after_insert after insert on file_data"
        $sql5 = "create trigger if not exists file_data_after_delete after delete on file_data"
        $sql6 = "create trigger if not exists file_data_after_update after update on file_data"
        $sql7 = "insert into file_data(file_id, ofs, data, status)"

    condition:
        uint16(0) == 0x5a4d and (any of ($s*) or #fc_msg >= 8 or 4 of ($sql*))
}

rule apt_Windows_TA410_Rootkit_strings
{
    meta:
        description = "Strings found in TA410's Rootkit"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    strings:
        $driver1 = "\\Driver\\kbdclass" wide
        $driver2 = "\\Driver\\mouclass" wide
        $device1 = "\\Device\\KeyboardClass0" wide
        $device2 = "\\Device\\PointerClass0" wide
        $driver3 = "\\Driver\\tcpip" wide
        $device3 = "\\Device\\tcp" wide
        $driver4 = "\\Driver\\nsiproxy" wide
        $device4 = "\\Device\\Nsi" wide
        $reg1 = "\\Registry\\Machine\\SYSTEM\\Setup\\AllowStart\\ceipCommon" wide
        $reg2 = "RHH%d" wide
        $reg3 = "RHP%d" wide
        $s1 = "\\SystemRoot\\System32\\drivers\\hidmouse.sys" wide

    condition:
        uint16(0) == 0x5a4d and all of ($s1,$reg*) and (all of ($driver*) or all of ($device*))
}

rule apt_Windows_TA410_FlowCloud_v5_resources
{
    meta:
        description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 5.0.2"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    condition:
        uint16(0) == 0x5a4d and pe.number_of_resources >= 13 and
        for 12 resource in pe.resources:
        ( resource.type == 10 and resource.language == 1033 and
            //resource name is one of 100, 1000, 10000, 1001, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 2000, 2001 as widestring
            (resource.name_string == "1\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x000\x00" or
             resource.name_string == "1\x000\x000\x001\x00" or resource.name_string == "1\x000\x001\x00" or resource.name_string == "1\x000\x002\x00" or
             resource.name_string == "1\x000\x003\x00" or resource.name_string == "1\x000\x004\x00" or resource.name_string == "1\x000\x005\x00" or
             resource.name_string == "1\x000\x006\x00" or resource.name_string == "1\x000\x007\x00" or resource.name_string == "1\x000\x008\x00" or
             resource.name_string == "1\x000\x009\x00" or resource.name_string == "1\x001\x000\x00" or resource.name_string == "2\x000\x000\x000\x00" or resource.name_string == "2\x000\x000\x001\x00")
        )
}

rule apt_Windows_TA410_FlowCloud_v4_resources
{
    meta:
        description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 4.1.3"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    condition:
        uint16(0) == 0x5a4d and pe.number_of_resources >= 6 and
        for 5 resource in pe.resources:
        ( resource.type == 10 and resource.language == 1033 and
            // resource name is one of 10000, 10001, 10002, 10003, 10004, 10005, 10100 as wide string
            (resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x001\x00" or
             resource.name_string == "1\x000\x000\x000\x002\x00" or resource.name_string == "1\x000\x000\x000\x003\x00" or
             resource.name_string == "1\x000\x000\x000\x004\x00" or resource.name_string == "1\x000\x000\x000\x005\x00" or resource.name_string == "1\x000\x001\x000\x000\x00")
        )
}
