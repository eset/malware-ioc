import "elf"

rule libkeyutils_with_ctor
{
    meta:
        description = "This rule detects if a libkeyutils.so shared library has a potentially malicious function to be called when loaded, either via a glibc constructor (DT_INIT + .ctors) or an initializer function in DT_INIT_ARRAY."
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2024-02-01"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
        version = 2
        last_modified = "2024-04-29"

    strings:
        $libname = "libkeyutils.so.1"

    condition:
        for any ptr_size in (4,8): (
            (
                (ptr_size == 4 and elf.machine == elf.EM_386)
                or
                (ptr_size == 8 and elf.machine == elf.EM_X86_64)
            )
            and
            for any d in elf.dynamic: (
                d.type == elf.DT_SONAME
                and
                (
                    for any s in elf.sections: (
                        s.name == ".dynstr" and
                        $libname at (s.offset + d.val)
                    )
                    or
                    for any s in elf.dynamic: (
                        s.type == elf.DT_STRTAB and
                        $libname at (s.val + d.val)
                    )
                )
            )
            and
            (
                for any s in elf.sections: (
                    s.name == ".ctors" and s.size > 2 * ptr_size
                )
                or
                for any d in elf.dynamic: (
                    d.type == elf.DT_INIT_ARRAYSZ and d.val > ptr_size
                )
            )
        )
}

rule Ebury_v1_7_crypto
{
    meta:
        description = "This rule detects the strings decryption routine in Ebury v1.7 and v1.8"
        author = "Marc-Etienne M.Léveillé <leveille@eset.com>"
        copyright = "ESET, spol. s r.o."
        license = "BSD 2-Clause"
        date = "2023-08-01"
        reference = "https://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        hash = "e7debd6e453192ad8376db5bab03ed0d87566591"
        version = 1
        last_modified = "2024-04-29"

    strings:
        $64 = {
            48 69 ( 9C 24 ?? ?? ?? ?? | 5C 24 ?? | D2) 6D 4E C6 41 //  imul    rbx, [rsp+_buf], 41C64E6Dh
            8B (0C 16 | 34 07)                      //  mov     ecx, [rsi+rdx]
            48 81 C? 39 30 00 00                    //  add     rbx, 12345
            ( 31 D? |                               //  xor     ecx, ebx
              31 D? 48 89 9C 24 ?? ?? ?? ?? |       //  mov     [rsp+_buf], rbx
              31 D? 48 89 5C 24 ?? )                //  ^ optional
            89 (0C 10 | 34 01)                      //  mov     [rax+rdx], ecx
            48 83 C? 04                             //  add     rdx, 4
            48 (81 FA | 3D ) ?? ?? ?? ??            //  cmp     rdx, _size
            75 D?                                   //  jnz     short _begin
        }

        $32 = {
            69 C9 6D 4E C6 41      // imul    ecx, 41C64E6Dh
            8B B4 1A ?? ?? ?? ??   // mov     esi, [edx+ebx+_data]
            81 C1 39 30 00 00      // add     ecx, 12345
            31 CE                  // xor     esi, ecx
            89 34 10               // mov     [eax+edx], esi
            83 C2 04               // add     edx, 4
            81 FA ?? ?? ?? ??      // cmp     edx, _size
            75 DD                  // jnz     short loc_69A5
        }

    condition:
        any of them
}
