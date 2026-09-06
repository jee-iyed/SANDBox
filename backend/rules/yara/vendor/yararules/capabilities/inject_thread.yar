/*
    Extracted without semantic changes from
    Yara-Rules/rules/capabilities/capabilities.yar rule inject_thread.
    Revision: 0f93570194a80d2f2032869055808b0ddcdfb360
    License: GPL-2.0
*/
rule inject_thread
{
    meta:
        author = "x0r"
        description = "Code injection with CreateRemoteThread in a remote process"
        version = "0.1"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess"
    condition:
        $c1 and $c2 and ($c3 or $c4) and ($c5 or $c6 or $c7)
}
