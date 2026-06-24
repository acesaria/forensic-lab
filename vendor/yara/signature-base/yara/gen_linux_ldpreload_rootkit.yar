rule SUSP_LD_PRELOAD_Hook_SharedObject {
    meta:
        description = "Detects a shared object that hooks libc symbols, typical of an LD_PRELOAD userland rootkit"
        author = "forensic-lab vendored subset (Neo23x0 signature-base)"
        reference = "https://github.com/Neo23x0/signature-base"
        date = "2026-06-14"
        technique = "attack.t1574.006"
    strings:
        $pre = "ld.so.preload" ascii
        $sym1 = "getuid" ascii
        $sym2 = "readdir" ascii
        $sym3 = "dlsym" ascii
        $sym4 = "RTLD_NEXT" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of ($sym*) and $pre
}

rule SUSP_Linux_Reverse_Shell_Indicators {
    meta:
        description = "Detects common reverse-shell command fragments embedded in files"
        author = "forensic-lab vendored subset (Neo23x0 signature-base)"
        reference = "https://github.com/Neo23x0/signature-base"
        date = "2026-06-14"
        technique = "attack.t1059.004"
    strings:
        $a = "mkfifo" ascii
        $b = "/dev/tcp/" ascii
        $c = "bash -i" ascii
    condition:
        2 of them
}
