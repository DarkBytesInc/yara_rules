rule Win_Trojan_Keylogger_123
{
strings:
	$a0 = { 4c006f00670073002000660072006f006d002000760069006300740069006d000000000042006f0064007900000000002400000043003a005c00770069006e0064006f00770073005c006c006f0067002e00740078007400000000004100640064004100740074006100630068006d0065006e0074000000530065006e0064000000000064006900730063006f006e006e00650063007400000000002400000043003a005c00570069006e0064006f00770073005c006c006f0067002e007400780074 }

condition:
	$a0
}

        