rule Win_Trojan_BAT_83
{
strings:
	$a0 = { 406563686f2040676f746f206d65746b613e3e633a5c6175746f657865632e626174 }

condition:
	$a0
}

        
