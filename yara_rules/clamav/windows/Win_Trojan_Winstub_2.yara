rule Win_Trojan_Winstub_2
{
strings:
	$a0 = { 6f01b409cd21cd20721dba9e00b8013dcd2193b440b9d600ba0001cd21b43ecd21b44fcd2173e1 }

condition:
	$a0
}

        
