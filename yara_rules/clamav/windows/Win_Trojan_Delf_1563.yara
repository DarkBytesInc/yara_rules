rule Win_Trojan_Delf_1563
{
strings:
	$a0 = { 6a006a0068484a4100ff356466410068984a41008d45d0ba03000000e83cf1ffff8b45d0e874f2ffff50689c4a410068a04a41006a00e8b6f7ffffe855f9ffff }

condition:
	$a0
}

        
