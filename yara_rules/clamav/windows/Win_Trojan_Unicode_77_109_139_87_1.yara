rule Win_Trojan_Unicode_77_109_139_87_1
{
strings:
	$a0 = { 370037002e003100300039002e003100330039002e00380037 }

condition:
	$a0
}

        
