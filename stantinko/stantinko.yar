// Stantinko yara rules
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

rule beds_plugin {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko BEDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("CheckDLLStatus") and
        pe.exports("GetPluginData") and
        pe.exports("InitializePlugin") and
        pe.exports("IsReleased") and
        pe.exports("ReleaseDLL")
}

rule beds_dropper {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "BEDS dropper"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.imphash() == "a7ead4ef90d9981e25728e824a1ba3ef"
        
}

rule facebook_bot {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko's Facebook bot"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "m_upload_pic&return_uri=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
        $s2 = "D:\\work\\brut\\cms\\facebook\\facebookbot\\Release\\facebookbot.pdb" fullword ascii
        $s3 = "https%3A%2F%2Fm.facebook.com%2Fcomment%2Freplies%2F%3Fctoken%3D" fullword ascii
        $s4 = "reg_fb_gate=https%3A%2F%2Fm.facebook.com%2Freg" fullword ascii
        $s5 = "reg_fb_ref=https%3A%2F%2Fm.facebook.com%2Freg%2F" fullword ascii
        $s6 = "&return_uri_error=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii

        $x1 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword ascii
        $x2 = "registration@facebookmail.com" fullword ascii
        $x3 = "https://m.facebook.com/profile.php?mds=" fullword ascii
        $x4 = "https://upload.facebook.com/_mupload_/composer/?profile&domain=" fullword ascii
        $x5 = "http://staticxx.facebook.com/connect/xd_arbiter.php?version=42#cb=ff43b202c" fullword ascii
        $x6 = "https://upload.facebook.com/_mupload_/photo/x/saveunpublished/" fullword ascii
        $x7 = "m.facebook.com&ref=m_upload_pic&waterfall_source=" fullword ascii
        $x8 = "payload.commentID" fullword ascii
        $x9 = "profile.login" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($s*) or 3 of ($x*) ) ) or ( all of them )
}

rule pds_plugins {
 
    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko PDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "std::_Vector_val<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s2 = "std::_Vector_val<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s3 = "std::vector<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s4 = "std::vector<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s5 = "CHTTPHeaderManager" fullword ascii
        $s6 = "CHTTPPostItemManager *" fullword ascii
        $s7 = "CHTTPHeaderManager *" fullword ascii
        $s8 = "CHTTPPostItemManager" fullword ascii
        $s9 = "CHTTPHeader" fullword ascii
        $s10 = "CHTTPPostItem" fullword ascii
        $s11 = "std::vector<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s12 = "std::_Vector_val<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s13 = "CCookieManager *" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 2 of ($s*) ) )
}

rule stantinko_pdb {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko malware family PDB path"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "D:\\work\\service\\service\\" ascii

    condition:
        all of them
}

rule stantinko_droppers {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko droppers"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Bytes from the encrypted payload
        $s1 = {55 8B EC 83 EC 08 53 56 BE 80 F4 45 00 57 81 EE 80 0E 41 00 56 E8 6D 23 00 00 56 8B D8 68 80 0E 41 00 53 89 5D F8 E8 65 73 00 00 8B 0D FC F5 45}

        // Keys to decrypt payload
        $s2 = {7E 5E 7F 8C 08 46 00 00 AB 57 1A BB 91 5C 00 00 FA CC FD 76 90 3A 00 00}

    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule stantinko_d3d {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko d3dadapter component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("EntryPoint") and
        pe.exports("ServiceMain") and
        pe.imports("WININET.DLL", "HttpAddRequestHeadersA")
}

rule stantinko_ihctrl32 {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ihctrl32 component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "ihctrl32.dll"
        $s2 = "win32_hlp"
        $s3 = "Ihctrl32Main"
        $s4 = "I%citi%c%size%s%c%ci%s"
        $s5 = "Global\\Intel_hctrl32"

    condition:
        2 of them
}

rule stantinko_wsaudio {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko wsaudio component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Export
        $s1 = "GetInterface"
        $s2 = "wsaudio.dll"

        // Event name
        $s3 = "Global\\Wsaudio_Initialize"
        $s4 = "SOFTWARE\\Classes\\%s.FieldListCtrl.1\\"

    condition:
        2 of them
}

rule stantinko_ghstore {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ghstore component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "G%cost%sSt%c%s%s%ce%sr" wide
        $s2 = "%cho%ct%sS%sa%c%s%crve%c" wide
        $s3 = "Par%c%ce%c%c%s" wide
        $s4 = "S%c%curity%c%s%c%s" wide
        $s5 = "Sys%c%s%c%c%su%c%s%clS%c%s%serv%s%ces" wide

    condition:
        3 of them
}
