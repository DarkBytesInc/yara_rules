rule Win_Trojan_Startpage_385
{
strings:
	$a0 = { 2e636e0000000000000000000064793930382e636f6d00000000000000363738396f6b2e636f6d000000000000536f6674776172655c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c4d61696e00000044656661756c745f506167655f55524c000000004c6f }

condition:
	$a0
}

        