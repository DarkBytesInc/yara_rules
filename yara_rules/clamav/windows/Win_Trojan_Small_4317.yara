rule Win_Trojan_Small_4317
{
strings:
	$a0 = { e8??000000[0-255]bb6764b20f81f36764f20f81e889f226262d77c9d8d98d3405000000008d7433008db634ff0000 }

condition:
	$a0
}

        
