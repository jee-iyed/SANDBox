/* SANDBox-owned rules. No third-party license applies to this file. */

rule SANDBOX_M4_TEST_MARKER
{
    meta:
        description = "Deterministic harmless marker used only by the M4 controlled corpus"
        severity = "medium"
        category = "test"
    strings:
        $marker = "SANDBOX_M4_YARA_TEST_MARKER"
    condition:
        $marker
}

rule SANDBOX_PDF_ACTIVE_CONTENT
{
    meta:
        description = "PDF contains an active JavaScript/open action combination"
        severity = "medium"
        category = "pdf"
    strings:
        $pdf = "%PDF"
        $js = "/JavaScript" nocase
        $action = "/OpenAction" nocase
    condition:
        $pdf at 0 and $js and $action
}
