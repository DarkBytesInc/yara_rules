rule Win_Trojan_Nazi_2
{
strings:
	$a0 = { 9a000035005589e5e8a7fde856ffbf54131e57bf0a020e5731c0509a150635009a820535005d31c09a16013500000000 }

condition:
	$a0
}

        
