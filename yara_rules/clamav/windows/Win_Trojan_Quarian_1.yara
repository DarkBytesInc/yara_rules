rule Win_Trojan_Quarian_1
{
strings:
	$a0 = { 50726f78792d436f6e6e6574696f6e3a204b6565702d416c697665[131]436f6e74656e745f6c656e6774683a2030 }

condition:
	$a0
}

        
