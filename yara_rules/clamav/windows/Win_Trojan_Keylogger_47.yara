rule Win_Trojan_Keylogger_47
{
strings:
	$a0 = { 3a5c244b616e4c6f676765722e64656c000000538bd86840524000536a006a00e8fed3ffff66a3d47640005bc38bc0538bd86854 }

condition:
	$a0
}

        
