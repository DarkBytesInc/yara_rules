rule Win_Trojan_Packed_114
{
strings:
	$a0 = { 558bec83c4f0b8??2?0070e8????ffff5?5?83f?004?4?83e?01 }

condition:
	$a0
}

        
