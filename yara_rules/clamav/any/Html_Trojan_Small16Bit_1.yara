rule Html_Trojan_Small16Bit_1
{
strings:
	$a0 = { 38312e3233322e38372e3635207365 }

condition:
	$a0
}

        
