rule Win_Downloader_Small_488
{
strings:
	$a0 = { 77732055706461746520436865636b6572004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c73797374656d33325c73797374656d5f }
	$a1 = { 58585858585858585858687474703a2f2f }

condition:
	$a0 and $a1
}

        