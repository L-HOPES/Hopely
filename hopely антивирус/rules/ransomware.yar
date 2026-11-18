/* Признаки шифровальщиков, вайперов и стилеров. */

rule Ransomware_Note
{
    meta:
        description = "Текст записки о выкупе"
        severity = "high"
    strings:
        $n1 = "your files have been encrypted" ascii wide nocase
        $n2 = "all your files are encrypted" ascii wide nocase
        $n3 = "to decrypt your files" ascii wide nocase
        $n4 = "bitcoin" ascii wide nocase
    condition:
        $n1 or $n2 or ($n3 and $n4)
}

rule Ransomware_Extensions
{
    meta:
        description = "Расширения и имена файлов-записок шифровальщиков"
        severity = "high"
    strings:
        $e1 = ".locked" ascii wide nocase
        $e2 = ".crypt" ascii wide nocase
        $e3 = ".wncry" ascii wide nocase
        $e4 = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $e5 = "HOW_TO_RESTORE" ascii wide nocase
        $e6 = "RECOVER_FILES" ascii wide nocase
    condition:
        any of them
}

rule Wiping_Behavior
{
    meta:
        description = "Уничтожение данных: перезапись диска и удаление теневых копий"
        severity = "high"
    strings:
        $w1 = "vssadmin delete shadows" ascii wide nocase
        $w2 = "wbadmin delete catalog" ascii wide nocase
        $w3 = "cipher /w:" ascii wide nocase
        $w4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $w5 = "\\\\.\\PhysicalDrive" ascii wide
    condition:
        any of them
}

rule Credential_Stealer
{
    meta:
        description = "Сбор паролей из браузеров, мессенджеров и хранилища Windows"
        severity = "high"
    strings:
        $c1 = "Login Data" ascii wide
        $c2 = "Local State" ascii wide
        $c3 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $c4 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $c5 = "CryptUnprotectData" ascii nocase
        $c6 = "\\Discord\\Local Storage\\leveldb" ascii wide nocase
        $c7 = "\\Telegram Desktop\\tdata" ascii wide nocase
    condition:
        ($c5 and 2 of ($c1, $c3, $c4, $c6, $c7)) or 3 of them
}

rule Miner_Pool
{
    meta:
        description = "Строки подключения к пулу для майнинга криптовалюты"
        severity = "medium"
    strings:
        $m1 = "stratum+tcp://" ascii wide nocase
        $m2 = "stratum+ssl://" ascii wide nocase
        $m3 = "xmrig" ascii wide nocase
        $m4 = "nicehash" ascii wide nocase
    condition:
        any of them
}