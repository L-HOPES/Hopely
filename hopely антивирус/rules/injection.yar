/* Признаки внедрения кода в чужие процессы и закрепления в системе. */

rule Process_Injection_API
{
    meta:
        description = "Набор Windows API для инъекции в чужой процесс"
        severity = "high"
    strings:
        $a1 = "VirtualAllocEx" ascii nocase
        $a2 = "WriteProcessMemory" ascii nocase
        $a3 = "CreateRemoteThread" ascii nocase
        $b1 = "NtUnmapViewOfSection" ascii nocase
        $b2 = "SetThreadContext" ascii nocase
        $b3 = "QueueUserAPC" ascii nocase
    condition:
        ((1 of ($a*)) and (1 of ($a*))) or ((1 of ($b*)) and (2 of ($b*)))
}

rule Persistence_Registry_Run
{
    meta:
        description = "Автозапуск через ключи Run/RunOnce реестра"
        severity = "medium"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
    condition:
        any of them
}

rule Defender_Tampering
{
    meta:
        description = "Попытка отключить защитник Windows или антивирус"
        severity = "high"
    strings:
        $d1 = "DisableAntiSpyware" ascii wide nocase
        $d2 = "DisableRealtimeMonitoring" ascii wide nocase
        $d3 = "WinDefend" ascii wide nocase
        $d4 = "Set-MpPreference" ascii wide nocase
    condition:
        2 of them
}

rule Anti_Debug_Tricks
{
    meta:
        description = "Проверки на отладчик и виртуальную машину"
        severity = "low"
    strings:
        $a1 = "CheckRemoteDebuggerPresent" ascii nocase
        $a2 = "IsDebuggerPresent" ascii nocase
        $a3 = "NtQueryInformationProcess" ascii nocase
        $v1 = "VMwareVMware" ascii wide
        $v2 = "VBoxService" ascii wide
        $v3 = "SbieDll.dll" ascii wide
    condition:
        2 of them
}