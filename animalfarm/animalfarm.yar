// Animal Farm yara rules
// For feedback or questions contact us at: github@eset.com
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

rule ramFS
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "RamFS -- custom file system used by Animal Farm malware"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $mz = { 4d 5a }

        // Debug strings in RamFS
        $s01 = "Check: Error in File_List"
        $s02 = "Check: Error in FreeFileHeader_List"
        $s03 = "CD-->[%s]"
        $s04 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]"
        // RamFS parameters stored in the configuration
        $s05 = "tr4qa589" fullword
        $s06 = "xT0rvwz" fullword

        // RamFS commands
        $c01 = "INSTALL" fullword
        $c02 = "EXTRACT" fullword
        $c03 = "DELETE" fullword
        $c04 = "EXEC" fullword
        $c05 = "INJECT" fullword
        $c06 = "SLEEP" fullword
        $c07 = "KILL" fullword
        $c08 = "AUTODEL" fullword
        $c09 = "CD" fullword
        $c10 = "MD" fullword        

    condition:
        ( $mz at 0 ) and
            ((1 of ($s*)) or (all of ($c*)))
}

rule dino
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "Dino backdoor"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $ = "PsmIsANiceM0du1eWith0SugarInsideA"
        $ = "destroyPSM"
        $ = "FM_PENDING_DOWN_%X"
        $ = "%s was canceled after %d try (reached MaxTry parameter)"
        $ = "you forgot value name"
        $ = "wakeup successfully scheduled in %d minutes"
        $ = "BD started at %s"
        $ = "decyphering failed on bd"

    condition:
        any of them
}