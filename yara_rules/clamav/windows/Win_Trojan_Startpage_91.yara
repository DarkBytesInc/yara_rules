rule Win_Trojan_Startpage_91
{
strings:
	$a0 = { ff0300000073707900ffffffff040000002d63616d00000000ffffffff110000002e6e65742f3f746f706f74756e2e636f6d000000ffffffff0300000053505900ffffffff0300000043414d00ffffffff0a000000687474703a2f2f7765620000ffffffff060000002d63616d }

condition:
	$a0
}

        