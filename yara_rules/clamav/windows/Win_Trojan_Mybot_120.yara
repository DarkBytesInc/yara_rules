rule Win_Trojan_Mybot_120
{
strings:
	$a0 = { 53e46d2045ff1b08f7e87433f95c524156454e53484945ae8b1b884c1e004e61fd7242e880fd896394323030337f456cdbf1ffef27726f6e }

condition:
	$a0
}

        
