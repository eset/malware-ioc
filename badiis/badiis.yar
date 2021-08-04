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

private rule IIS_Native_Module {
    meta:
        description = "Signature to match an IIS native module (clean or malicious)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $e1 = "This module subscribed to event"
        $e2 = "CHttpModule::OnBeginRequest"
        $e3 = "CHttpModule::OnPostBeginRequest"
        $e4 = "CHttpModule::OnAuthenticateRequest"
        $e5 = "CHttpModule::OnPostAuthenticateRequest"
        $e6 = "CHttpModule::OnAuthorizeRequest"
        $e7 = "CHttpModule::OnPostAuthorizeRequest"
        $e8 = "CHttpModule::OnResolveRequestCache"
        $e9 = "CHttpModule::OnPostResolveRequestCache"
        $e10 = "CHttpModule::OnMapRequestHandler"
        $e11 = "CHttpModule::OnPostMapRequestHandler"
        $e12 = "CHttpModule::OnAcquireRequestState"
        $e13 = "CHttpModule::OnPostAcquireRequestState"
        $e14 = "CHttpModule::OnPreExecuteRequestHandler"
        $e15 = "CHttpModule::OnPostPreExecuteRequestHandler"
        $e16 = "CHttpModule::OnExecuteRequestHandler"
        $e17 = "CHttpModule::OnPostExecuteRequestHandler"
        $e18 = "CHttpModule::OnReleaseRequestState"
        $e19 = "CHttpModule::OnPostReleaseRequestState"
        $e20 = "CHttpModule::OnUpdateRequestCache"
        $e21 = "CHttpModule::OnPostUpdateRequestCache"
        $e22 = "CHttpModule::OnLogRequest"
        $e23 = "CHttpModule::OnPostLogRequest"
        $e24 = "CHttpModule::OnEndRequest"
        $e25 = "CHttpModule::OnPostEndRequest"
        $e26 = "CHttpModule::OnSendResponse"
        $e27 = "CHttpModule::OnMapPath"
        $e28 = "CHttpModule::OnReadEntity"
        $e29 = "CHttpModule::OnCustomRequestNotification"
        $e30 = "CHttpModule::OnAsyncCompletion"
        $e31 = "CGlobalModule::OnGlobalStopListening"
        $e32 = "CGlobalModule::OnGlobalCacheCleanup"
        $e33 = "CGlobalModule::OnGlobalCacheOperation"
        $e34 = "CGlobalModule::OnGlobalHealthCheck"
        $e35 = "CGlobalModule::OnGlobalConfigurationChange"
        $e36 = "CGlobalModule::OnGlobalFileChange"
        $e37 = "CGlobalModule::OnGlobalApplicationStart"
        $e38 = "CGlobalModule::OnGlobalApplicationResolveModules"
        $e39 = "CGlobalModule::OnGlobalApplicationStop"
        $e40 = "CGlobalModule::OnGlobalRSCAQuery"
        $e41 = "CGlobalModule::OnGlobalTraceEvent"
        $e42 = "CGlobalModule::OnGlobalCustomNotification"
        $e43 = "CGlobalModule::OnGlobalThreadCleanup"
        $e44 = "CGlobalModule::OnGlobalApplicationPreload"    
    
    condition:
        uint16(0) == 0x5A4D and pe.exports("RegisterModule") and any of ($e*)
}

rule IIS_Group01_IISRaid {

    meta:
        description = "Detects Group 1 native IIS malware family (IIS-Raid derivates)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "cmd.exe" ascii wide
        $s2 = "CMD"
        $s3 = "PIN"
        $s4 = "INJ"
        $s5 = "DMP"
        $s6 = "UPL"
        $s7 = "DOW"
        $s8 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        
        $p1 = "C:\\Windows\\Temp\\creds.db"
        $p2 = "C:\\Windows\\Temp\\thumbs.db"
        $p3 = "C:\\Windows\\Temp\\AAD30E0F.tmp"
        $p4 = "X-Chrome-Variations"
        $p5 = "X-Cache"
        $p6 = "X-Via"
        $p7 = "COM_InterProt"
        $p8 = "X-FFEServer"
        $p9 = "X-Content-Type-Options"
        $p10 = "Strict-Transport-Security"
        $p11 = "X-Password"
        $p12 = "XXXYYY-Ref"
        $p13 = "X-BLOG"
        $p14 = "X-BlogEngine"

    condition:
        IIS_Native_Module and 3 of ($s*) and any of ($p*)
}

rule IIS_Group02 {

    meta:
        description = "Detects Group 2 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "HttpModule.pdb" ascii wide
        $s2 = "([\\w+%]+)=([^&]*)"
        $s3 = "([\\w+%]+)=([^!]*)"
        $s4 = "cmd.exe"
        $s5 = "C:\\Users\\Iso\\Documents\\Visual Studio 2013\\Projects\\IIS 5\\x64\\Release\\Vi.pdb" ascii wide
        $s6 = "AVRSAFunction"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group03 {

    meta:
        description = "Detects Group 3 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "IIS-Backdoor.dll" 
        $s2 = "CryptStringToBinaryA"
        $s3 = "CreateProcessA"
        $s4 = "X-Cookie"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group04_RGDoor {

    meta:
        description = "Detects Group 4 native IIS malware family (RGDoor)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        reference = "https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $i1 = "RGSESSIONID="
        $s2 = "upload$"
        $s3 = "download$"
        $s4 = "cmd$"
        $s5 = "cmd.exe"

    condition:
        IIS_Native_Module and ($i1 or all of ($s*))
}

rule IIS_Group05_IIStealer {

    meta:
        description = "Detects Group 5 native IIS malware family (IIStealer)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "tojLrGzFMbcDTKcH" ascii wide
        $s2 = "4vUOj3IutgtrpVwh" ascii wide
        $s3 = "SoUnRCxgREXMu9bM" ascii wide
        $s4 = "9Zr1Z78OkgaXj1Xr" ascii wide
        $s5 = "cache.txt" ascii wide
        $s6 = "/checkout/checkout.aspx" ascii wide
        $s7 = "/checkout/Payment.aspx" ascii wide
        $s8 = "/privacy.aspx"
        $s9 = "X-IIS-Data"
        $s10 = "POST"

        // string stacking of "/checkout/checkout.aspx"
        $s11 = {C7 ?? CF 2F 00 63 00 C7 ?? D3 68 00 65 00 C7 ?? D7 63 00 6B 00 C7 ?? DB 6F 00 75 00 C7 ?? DF 74 00 2F 00 C7 ?? E3 63 00 68 00 C7 ?? E7 65 00 63 00 C7 ?? EB 6B 00 6F 00 C7 ?? EF 75 00 74 00 C7 ?? F3 2E 00 61 00 C7 ?? F7 73 00 70 00 C7 ?? FB 78 00 00 00}

        // string stacking of "/privacy.aspx"
        $s12 = {C7 ?? AF 2F 00 70 00 C7 ?? B3 72 00 69 00 C7 ?? B7 76 00 61 00 C7 ?? BB 63 00 79 00 C7 ?? BF 2E 00 61 00 C7 ?? C3 73 00 70 00 C7 ?? C7 78 00 00 00}

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group06_ISN {

    meta:
        description = "Detects Group 6 native IIS malware family (ISN)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/the-curious-case-of-the-malicious-iis-module/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "isn7 config reloaded"
        $s2 = "isn7 config NOT reloaded, not found or empty"
        $s3 = "isn7 log deleted"
        $s4 = "isn7 log not deleted, ERROR 0x%X"
        $s5 = "isn7 log NOT found"
        $s6 = "isn_reloadconfig"
        $s7 = "D:\\soft\\Programming\\C++\\projects\\isapi\\isn7"
        $s8 = "get POST failed %d"
        $s9 = "isn7.dll"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group07_IISpy {

    meta:
        description = "Detects Group 7 native IIS malware family (IISpy)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $s1 = "/credential/username"
        $s2 = "/credential/password"
        $s3 = "/computer/domain"
        $s4 = "/computer/name"
        $s5 = "/password"
        $s6 = "/cmd"
        $s7 = "%.8s%.8s=%.8s%.16s%.8s%.16s"
        $s8 = "ImpersonateLoggedOnUser"
        $s9 = "WNetAddConnection2W"

        $t1 = "X-Forwarded-Proto"
        $t2 = "Sec-Fetch-Mode"
        $t3 = "Sec-Fetch-Site"
        $t4 = "Cookie"

        // PNG IEND
        $t5 = {49 45 4E 44 AE 42 60 82}

        // PNG HEADER
        $t6 = {89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52}

    condition:
        IIS_Native_Module and 2 of ($s*) and any of ($t*)
}

rule IIS_Group08 {

    meta:
        description = "Detects Group 8 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings:
        $i1 = "FliterSecurity.dll"
        $i2 = "IIS7NativeModule.dll"
        $i3 = "Ver1.0."

        $s1 = "Cmd"
        $s2 = "Realy path : %s"
        $s3 = "Logged On Users : %d"
        $s4 = "Connect OK!"
        $s5 = "You are fucked!"
        $s6 = "Shit!Error"
        $s7 = "Where is the God!!"
        $s8 = "Shit!Download False!"
        $s9 = "Good!Run OK!"
        $s10 = "Shit!Run False!"
        $s11 = "Good!Download OK!"
        $s12 = "[%d]safedog"
        $s13 = "ed81bfc09d069121"
        $s14 = "a9478ef01967d190"
        $s15 = "af964b7479e5aea2"
        $s16 = "1f9e6526bea65b59"
        $s17 = "2b9e9de34f782d31"
        $s18 = "33cc5da72ac9d7bb"
        $s19 = "b1d71f4c2596cd55"
        $s20 = "101fb9d9e86d9e6c"
    
    condition:
        IIS_Native_Module and 1 of ($i*) and 3 of ($s*)
}

rule IIS_Group09 {

    meta:
        description = "Detects Group 9 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $i1 = "FliterSecurity.dll"
        $i2 = {56565656565656565656565656565656}
        $i3 = "app|hot|alp|svf|fkj|mry|poc|doc|20" xor
        $i4 = "yisouspider|yisou|soso|sogou|m.sogou|sogo|sogou|so.com|baidu|bing|360" xor
        $i5 = "baidu|m.baidu|soso|sogou|m.sogou|sogo|sogou|so.com|google|youdao" xor
        $i6 = "118|abc|1go|evk" xor

        $s1 = "AVCFuckHttpModuleFactory"
        $s2 = "X-Forward"
        $s3 = "fuck32.dat"
        $s4 = "fuck64.dat"
        $s5 = "&ipzz1="
        $s6 = "&ipzz2="
        $s7 = "&uuu="

        $s8 = "http://20.3323sf.c" xor
        $s9 = "http://bj.whtjz.c" xor
        $s10 = "http://bj2.wzrpx.c" xor
        $s11 = "http://cs.whtjz.c" xor
        $s12 = "http://df.e652.c" xor
        $s13 = "http://dfcp.yyphw.c" xor
        $s14 = "http://es.csdsx.c" xor
        $s15 = "http://hz.wzrpx.c" xor
        $s16 = "http://id.3323sf.c" xor
        $s17 = "http://qp.008php.c" xor
        $s18 = "http://qp.nmnsw.c" xor
        $s19 = "http://sc.300bt.c" xor
        $s20 = "http://sc.wzrpx.c" xor
        $s21 = "http://sf2223.c" xor
        $s22 = "http://sx.cmdxb.c" xor
        $s23 = "http://sz.ycfhx.c" xor
        $s24 = "http://xpq.0660sf.c" xor
        $s25 = "http://xsc.b1174.c" xor

    condition:
        IIS_Native_Module and any of ($i*) and 3 of ($s*)
}

rule IIS_Group10 {

    meta:
        description = "Detects Group 10 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "IIS7.dll"
        $s2 = "<title>(.*?)title(.*?)>"
        $s3 = "<meta(.*?)name(.*?)=(.*?)keywords(.*?)>"
        $s4 = "<meta(.*?)name(.*?)=(.*?)description(.*?)>"
        $s5 = "js.breakavs.co"
        $s6 = "&#24494;&#20449;&#32676;&#45;&#36187;&#36710;&#80;&#75;&#49;&#48;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#95;&#24184;&#36816;&#39134;&#33351;&#95;&#24184;&#36816;&#50;&#56;&#32676;"
        $s7 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#112;&#107;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#80;&#75;&#49;&#48;&#24494;&#20449;&#32676;&#44;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#36187;&#36710;&#32676;&#44;"
        $s8 = "&#21271;&#20140;&#36187;&#36710;&#24494;&#20449;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#12304;&#36827;&#32676;&#24494;&#20449;&#21495;&#102;&#117;&#110;&#53;&#55;&#54;&#52;&#52;&#12305;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;&#32676;&#44;&#21271;&#20140;&#24494;&#20449;&#36187;&#36710;"

        $e1 = "Baiduspider"
        $e2 = "Sosospider"
        $e3 = "Sogou web spider"
        $e4 = "360Spider"
        $e5 = "YisouSpider"
        $e6 = "sogou.com"
        $e7 = "soso.com"
        $e8 = "uc.cn"
        $e9 = "baidu.com"
        $e10 = "sm.cn"

    condition:
        IIS_Native_Module and 2 of ($e*) and 3 of ($s*)
}

rule IIS_Group11 {

    meta:
        description = "Detects Group 11 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "DnsQuery_A"
        $s2 = "&reurl="
        $s3 = "&jump=1"

        // encrypted "HTTP_cmd" (SUB 2)
        $s4 = "JVVRaeof" 

        // encrypted "lanke88" (SUB 2)
        $s5 = "ncpmg::0"

        // encrypted "xinxx.allsoulu[.]com" (SUB 2)
        $s6 = "zkpzz0cnnuqwnw0eqo" 

        // encrypted "http://www.allsoulu[.]com/1.php?cmdout=" (SUB 2)
        $s7 = "jvvr<11yyy0cnnuqwnw0eqo130rjrAeofqwv?"

    condition:
        IIS_Native_Module and 3 of ($s*)
}

rule IIS_Group12 {

    meta:
        description = "Detects Group 12 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\"
        $s2 = "F5XFFHttpModule.dll"
        $s3 = "gtest_redir"
        $s4 = "\\cmd.exe" nocase
        $s5 = "iuuq;00" // encrypted "http://" (ADD 1)
        $s6 = "?xhost="
        $s7 = "&reurl="
        $s8 = "?jump=1"
        $s9 = "app|zqb"
        $s10 = "ifeng|ivc|sogou|so.com|baidu|google|youdao|yahoo|bing|118114|biso|gougou|sooule|360|sm|uc"
        $s11 = "sogou|so.com|baidu|google|youdao|yahoo|bing|gougou|sooule|360|sm.cn|uc"
        $s12 = "Hotcss/|Hotjs/"
        $s13 = "HotImg/|HotPic/"
        $s14 = "msf connect error !!"
        $s15 = "download ok !!"
        $s16 = "download error !! "
        $s17 = "param error !!"
        $s18 = "Real Path: "
        $s19 = "unknown cmd !"

        // hardcoded hash values
        $b1 = {15 BD 01 2E [-] 5E 40 08 97 [-] CF 8C BE 30 [-] 28 42 C6 3B}
        $b2 = {E1 0A DC 39 [-] 49 BA 59 AB [-] BE 56 E0 57 [-] F2 0F 88 3E}

    condition:
        IIS_Native_Module and 5 of them
}

rule IIS_Group13_IISerpent {

    meta:
        description = "Detects Group 13 native IIS malware family (IISerpent)"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $s1 = "/mconfig/lunlian.txt"
        $s2 = "http://sb.qrfy.ne"
        $s3 = "folderlinkpath"
        $s4 = "folderlinkcount"
        $s5 = "onlymobilespider"
        $s6 = "redirectreferer"
        $s7 = "loadSuccessfull : "
        $s8 = "spider"
        $s9 = "<a href="
        $s11 = "?ReloadModuleConfig=1"
        $s12 = "?DisplayModuleConfig=1"

    condition:
        IIS_Native_Module and 5 of them
}

rule IIS_Group14 {

    meta:
        description = "Detects Group 14 native IIS malware family"
        author = "ESET Research"
        date = "2021-08-04"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"

    strings: 
        $i1 = "agent-self: %s"
        $i2 = "/utf.php?key="
        $i3 = "/self.php?v="
        $i4 = "<script type=\"text/javascript\" src=\"//speed.wlaspsd.co"
        $i5 = "now.asmkpo.co"

        $s1 = "Baiduspider"
        $s2 = "360Spider"
        $s3 = "Sogou"
        $s4 = "YisouSpider"
        $s6 = "HTTP_X_FORWARDED_FOR"


    condition:
        IIS_Native_Module and 2 of ($i*) or 5 of them
}