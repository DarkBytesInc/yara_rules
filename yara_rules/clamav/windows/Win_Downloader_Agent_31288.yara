rule Win_Downloader_Agent_31288
{
strings:
	$a0 = { 6f7841d57367498d2f2533322e642a3fe4f273cbce34d2030b82358635a242e8f206370a373d1551618323a9e40390662440e6ff5bfd5c74656d705c5777617563746c772e65786500fffdfffb6e2e7478741fcbced2cec5d2cac9d2cdccca }

condition:
	$a0
}

        