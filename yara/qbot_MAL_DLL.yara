import "pe"

rule qbot_MAL_DLL
{
    meta:
        description = "<word>"
        author = "<Aaron Dellamano>"
        date = "<October 17, 2025>"
        hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
    strings:

        // Variable prefix mapping
        // 1 - Grouping of nonstandard imports for msvcrt.dll unique from original libgdk-win32-2.0-0.dll binary
        // 2 - Grouping of nonstandard imports for kernel32.dll unique from original libgdk-win32-2.0-0.dll binary
        // 3 - Grouping of nonstandard imports for USER32.dll unique from original libgdk-win32-2.0-0.dll binary
        // 4 - Listing of any malicious functions identified within the file during debug analysis

        $s11 = "__setusermatherr"	            // May be used to perform overflow attacks or run malicious code in the binary execution state
        $s12 = "_amsg_exit"			            // Could be indication of behavior to terminate if detected
        $s13 = "_initterm"			            // Indication of behavior to initialize code before the normal program runs
        $s14 = "_lock"				            // Used for payload staging behavior
        $s15 = "_unlock"			            // Used for payload unpacking behavior
        $s16 = "fprintf"			            // Covert exfiltration indicator behavior
        $s17 = "isspace"			            // Indicator of decoding for parsing an obfuscated payload
        $s18 = "isxdigit"			            // Indication of assistor for hex-encoded malware
        $s19 = "memcmp"			                // Could indicate some level of memory buffer analysis for attack vector check behaviors
        $s110 ="strlen"				            // LOL type behavior
        $s111 ="strncmp"			            // LOL type behavior

        $s212 = "GetCurrentProcess"		        // Gives a process handle to malware, bad behavior
        $s213 = "GetSystemTimeAsFileTime"		// Behavior of associated with logic to detect VM/sandbox type enivronments or coupled with sleep for payload dormant periods
        $s214 = "QueryPerformanceCounter"		// LOL type behavior that could couple with VM/Sandbox detection
        $s215 = "SetUnhandledExceptionFilter"	// Behaivor indicating custom crash or exception handling that can obfuscate malware unpacking or hide these triggers
        $s216 = "Sleep"				            // Timing obfusctation and evading technique that can evade VM/Sanboxing
        $s217 = "TerminateProcess"		        // Can be used to abruptly kill the process to avoid analysis/forensics, to self-destruct on error, or to stop monitoring tools. Can be used for evidence cleanup.
        $s218 = "UnhandledExceptionFilter"      // May be used to forward exceptions to their handler or to restore original behavior to manipulate crash handling.

        $s319 = "GetKeyState"			        // Behavior assoicated with keylogger like activity
        $s320 = "GetKeyboardLayout"		        // Behavior assoicated with keylogger like activity
        $s321 = "GetKeyboardState"		        // Behavior assoicated with keylogger like activity
        $s322 = "GetUserObjectInformationA"	    // We saw WinSta0 in strings output and traced back to this import that determines if a process is on WinSta0\Default (interactive desktop), who owns it, or whether accessibility hooks might be abused.

        $s423 = "Updt"				            //Malicious funciton that appears to be responsible for unpacking shellcode




    condition:
        pe.is_pe and not
        pe.is_signed and
        filesize < 900KB and
        pe.exports("Tdk_wm_decoration_get_type") and	// Export observed in Updt function
        pe.exports("Tdk_gravity_get_type") and		    // Export observed in Updt function
        all of ($s1*) and
        all of ($s2*) and
        any of ($s3*) and
        any of ($s4*)
}