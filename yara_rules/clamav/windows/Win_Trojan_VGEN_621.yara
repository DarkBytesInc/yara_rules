rule Win_Trojan_VGEN_621
{
strings:
	$a0 = { 2d6c68312d2a04000095040000ab145a1820000641482e434f4d519174f96330f065b33b4e7ed759d0f6817d7e17 }

condition:
	$a0
}

        
