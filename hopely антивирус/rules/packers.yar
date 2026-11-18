/* Признаки упаковщиков и загрузчиков: файл сжат или распаковывается в памяти. */

rule UPX_Packed
{
    meta:
        description = "Файл упакован UPX — код сжат и не читается напрямую"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx  = "UPX!" ascii
    condition:
        2 of them
}

rule Common_Packer_Section
{
    meta:
        description = "Названия секций типичных упаковщиков (MPRESS, ASPack, Themida, Enigma)"
        severity = "medium"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".aspack" ascii
        $s3 = ".adata" ascii
        $s4 = ".themida" ascii
        $s5 = ".enigma1" ascii
        $s6 = ".vmp0" ascii
        $s7 = ".packed" ascii
    condition:
        any of them
}

rule VirtualMachine_Protector
{
    meta:
        description = "Признаки протектора с виртуализацией кода (VMProtect/Themida)"
        severity = "high"
    strings:
        $a = "VMProtect" ascii wide nocase
        $b = ".vmp1" ascii
        $c = "Themida" ascii wide nocase
    condition:
        any of them
}