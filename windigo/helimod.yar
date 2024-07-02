import "elf"

private rule ApacheModule
{
    meta:
        description = "Apache 2.4 module ELF shared library"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $magic = "42PA" // 'AP24' in LE

    condition:
        for any s in elf.dynsym: (
            s.type == elf.STT_OBJECT and
            for any seg in elf.segments: (
                seg.type == elf.PT_LOAD and
                s.value >= seg.virtual_address and
                s.value < (seg.virtual_address + seg.file_size) and
                $magic at (s.value - seg.virtual_address + seg.offset) + 0x28
            )
        )
}

rule HelimodProxy
{
    meta:
        description = "HelimodProxy malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $1 = "secret\x00%s:%u"
        $2 = "/%s/%s/%s%s"
        $3 = "ad\x00pmt"
        $4 = "mod_dir.c"
        $5 = "pmtad"
    condition:
        ApacheModule and ($1 or ($2 and $3) or ($4 and $5))
}

rule HelimodRedirect
{
    meta:
        description = "HelimodRedirect malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 1
        last_modified = "2024-04-27"

    strings:
        $h1 = "secret\x00%s:%"
        $h2 = "$!%#!$"
        $h3 = "mod_security2.c"
        $r1 = "%s?DOM=%s&URI=%s"
        $r2 = "REDIRECT_URL"

    condition:
        ApacheModule and any of ($h*) and any of ($r*)
}

rule HelimodSteal
{
    meta:
        description = "HelimodSteal malicious Apache module"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-04-27"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e39667aa137e315bc26eaef791ccab52938fd809"
        version = 2
        last_modified = "2024-04-27"

    strings:
        $h1 = "secret\x00%s:%"
        $h2 = "$!%#!$"
        $h3 = "mod_security2.c"
        $s1 = "p0sT5n1F3r"
        $s2 = "ENGINE_ON"
        $s3 = "POST /"

    condition:
        ApacheModule and any of ($h*) and any of ($s*)
}
