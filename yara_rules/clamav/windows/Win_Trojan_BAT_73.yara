rule Win_Trojan_BAT_73
{
strings:
	$a0 = { 406563686f206f666620636f707920253020633a5c6175746f657865632e626174 }

condition:
	$a0
}

        
