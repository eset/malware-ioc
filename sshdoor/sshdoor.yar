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

private rule ssh_client : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH client (ssh)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: ssh ["
        $old_version = "-L listen-port:host:port"

    condition:
        $usage or $old_version
}

private rule ssh_daemon : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Marc-Etienne M.Leveille"
        email  = "leveille@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: sshd ["
        $old_version = "Listen on the specified port (default: 22)"

    condition:
        $usage or $old_version
}

private rule ssh_add : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH add (ssh-add)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [file ...]\n"
        $log = "Could not open a connection to your authentication agent.\n"

    condition:
        $usage and $log
}

private rule ssh_agent : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH agent (ssh-agent)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [options] [command [arg ...]]"

    condition:
        $usage
}

private rule ssh_askpass : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH daemon (sshd)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter your OpenSSH passphrase:"
        $log = "Could not grab %s. A malicious client may be eavesdropping on you"

    condition:
        $pass and $log
}

private rule ssh_keygen : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keygen (ssh-keygen)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $pass = "Enter new passphrase (empty for no passphrase):"
        $log = "revoking certificates by key ID requires specification of a CA key"

    condition:
        $pass and $log
}

private rule ssh_keyscan : sshdoor {
    meta:
        description = "Signature to match the clean (or not) OpenSSH keyscan (ssh-keyscan)"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $usage = "usage: %s [-46Hv] [-f file] [-p port] [-T timeout] [-t type]"

    condition:
        $usage
}

private rule ssh_binary : sshdoor {
    meta:
        description = "Signature to match any clean (or not) SSH binary"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"

    condition:
        ssh_client or ssh_daemon or ssh_add or ssh_askpass or ssh_keygen or ssh_keyscan
}

private rule stack_string {
    meta:
        description = "Rule to detect use of string-stacking"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        // single byte offset from base pointer
        $bp = /(\xC6\x45.{2}){25}/
        // dword ss with single byte offset from base pointer
        $bp_dw = /(\xC7\x45.{5}){20}/
        // 4-bytes offset from base pointer
        $bp_off = /(\xC6\x85.{5}){25}/
        // single byte offset from stack pointer
        $sp = /(\xC6\x44\x24.{2}){25}/
        // 4-bytes offset from stack pointer
        $sp_off = /(\xC6\x84\x24.{5}){25}/

    condition:
        any of them
}

rule abafar {
    meta:
        description = "Rule to detect Abafar family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log_c =  "%s:%s@%s"
        $log_d =  "%s:%s from %s"

    condition:
        ssh_binary and any of them
}

rule akiva {
    meta:
        description = "Rule to detect Akiva family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /(To|From):\s(%s\s\-\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule alderaan {
    meta:
        description = "Rule to detect Alderaan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /login\s(in|at):\s(%s\s)?%s:%s\n/

    condition:
        ssh_binary and $log
}

rule ando {
    meta:
        description = "Rule to detect Ando family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s\n"
        $s2 = "HISTFILE"
        $i = "fopen64"
        $m1 = "cat "
        $m2 = "mail -s"

    condition:
        ssh_binary and all of ($s*) and ($i or all of ($m*))
}

rule anoat {
    meta:
        description = "Rule to detect Anoat family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%s at: %s | user: %s, pass: %s\n"

    condition:
        ssh_binary and $log
}

rule atollon {
    meta:
        description = "Rule to detect Atollon family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $f1 = "PEM_read_RSA_PUBKEY"
        $f2 = "RAND_add"
        $log = "%s:%s"
        $rand = "/dev/urandom"

    condition:
        ssh_binary and stack_string and all of them
}

rule batuu {
    meta:
        description = "Rule to detect Batuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $args = "ssh: ~(av[%d]: %s\n)"
        $log = "readpass: %s\n"

    condition:
        ssh_binary and any of them
}

rule bespin {
    meta:
        description = "Rule to detect Bespin family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log1 = "%Y-%m-%d %H:%M:%S"
        $log2 = "%s %s%s"
        $log3 = "[%s]"

    condition:
        ssh_binary and all of them
}

rule bonadan {
    meta:
        description = "Rule to detect Bonadan family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "g_server"
        $s2 = "mine.sock"
        $s3 = "tspeed"
        $e1 = "6106#x=%d#%s#%s#speed=%s"
        $e2 = "usmars.mynetgear.com"
        $e3 = "user=%s#os=%s#eip=%s#cpu=%s#mem=%s"

    condition:
        ssh_binary and any of them
}

rule borleias {
    meta:
        description = "Rule to detect Borleias family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "%Y-%m-%d %H:%M:%S [%s]"

    condition:
        ssh_binary and all of them
}

rule chandrila {
    meta:
        description = "Rule to detect Chandrila family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "S%s %s:%s"
        $magic = { 05 71 92 7D }

    condition:
        ssh_binary and all of them
}

rule coruscant {
    meta:
        description = "Rule to detect Coruscant family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "%s:%s@%s\n"
        $s2 = "POST"
        $s3 = "HTTP/1.1"

    condition:
        ssh_binary and all of them
}

rule crait {
    meta:
        description = "Signature to detect Crait family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $i1 = "flock"
        $i2 = "fchmod"
        $i3 = "sendto"

    condition:
        ssh_binary and 2 of them
}

rule endor {
    meta:
        description = "Rule to detect Endor family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $u = "user: %s"
        $p = "password: %s"

    condition:
        ssh_binary and $u and $p in (@u..@u+20)
}

rule jakuu {
    meta:
        description = "Rule to detect Jakuu family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        notes = "Strings can be encrypted"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $dec = /GET\s\/\?(s|c)id=/
        $enc1 = "getifaddrs"
        $enc2 = "usleep"
        $ns = "gethostbyname"
        $log = "%s:%s"
        $rc4 = { A1 71 31 17 11 1A 22 27 55 00 66 A3 10 FE C2 10 22 32 6E 95 90 84 F9 11 73 62 95 5F 4D 3B DB DC }

    condition:
        ssh_binary and $log and $ns and ($dec or all of ($enc*) or $rc4)
}

rule kamino {
    meta:
        description = "Rule to detect Kamino family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "/var/log/wtmp"
        $s2 = "/var/log/secure"
        $s3 = "/var/log/auth.log"
        $s4 = "/var/log/messages"
        $s5 = "/var/log/audit/audit.log"
        $s6 = "/var/log/httpd-access.log"
        $s7 = "/var/log/httpd-error.log"
        $s8 = "/var/log/xferlog"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "srand"
        $i4 = "gethostbyname"

    condition:
        ssh_binary and 5 of ($s*) and 3 of ($i*)
}

rule kessel {
    meta:
        description = "Rule to detect Kessel family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $rc4 = "Xee5chu1Ohshasheed1u"
        $s1 = "ssh:%s:%s:%s:%s"
        $s2 = "sshkey:%s:%s:%s:%s:%s"
        $s3 = "sshd:%s:%s"
        $i1 = "spy_report"
        $i2 = "protoShellCMD"
        $i3 = "protoUploadFile"
        $i4 = "protoSendReport"
        $i5 = "tunRecvDNS"
        $i6 = "tunPackMSG"

    condition:
        ssh_binary and (2 of ($s*) or 2 of ($i*) or $rc4)
}

rule mimban {
    meta:
        description = "Rule to detect Mimban family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $s1 = "<|||%s|||%s|||%d|||>"
        $s2 = />\|\|\|%s\|\|\|%s\|\|\|\d\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|</
        $s3 = "-----BEGIN PUBLIC KEY-----"
        $i1 = "BIO_f_base64"
        $i2 = "PEM_read_bio_RSA_PUBKEY"
        $i3 = "gethostbyname"

    condition:
        ssh_binary and 2 of ($s*) and 2 of ($i*)
}

rule ondaron {
    meta:
        description = "Rule to detect Ondaron family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $daemon = "user:password --> %s:%s\n"
        $client = /user(,|:)(a,)?password@host \-\-> %s(,|:)(b,)?%s@%s\n/

    condition:
        ssh_binary and ($daemon or $client)
}

rule polis_massa {
    meta:
        description = "Rule to detect Polis Massa family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = /\b\w+(:|\s-+>)\s%s(:%d)?\s\t(\w+)?:\s%s\s\t(\w+)?:\s%s/

    condition:
        ssh_binary and $log
}

rule quarren {
    meta:
        description = "Rule to detect Quarren family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $log = "h: %s, u: %s, p: %s\n"

    condition:
        ssh_binary and $log
}
