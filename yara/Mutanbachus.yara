import "pe"

rule mutanbachus_MAL
{
    meta:
        description = "Detects the Mutanbachus malware variant from the de&th demo."
        author = "<Aaron Dellamano>"
        date = "<October 17, 2025>"
        reference = "https://github.com/pr0xylife/Matanbuchus/blob/main/Matanbuchus_07.03_2024.txt/"
        hash = "1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b"
    strings:
        $s1 = "AppPolicyGetProcessTerminationMethod"
        $s2 = "** CHOSEN_DATA_PUM"
        $s3 = "DllRegisterServer"
        $s4 = "DllUnregisterServer"
        $s5 = "EmulateCallWaiting"
        $s6 = "win32.DLL"
        $s7 = "KERNEL32.dll"
        $s8 = "IsDebuggerPresent"
        $s9 = "OutputDebugStringW"
        $s10 = "DecodePointer"
        $s11 = "EncodePointer"
        $s12 = "Setting Dial Tone"
        $s13 = "EmulateCallWaiting"
    condition:
        pe.is_pe and
        filesize < 750KB and
        pe.imports("KERNEL32.dll","IsDebuggerPresent") and
        pe.exports("DllRegisterServer") and
        all of ($s*)
}