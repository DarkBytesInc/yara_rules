rule Html_Trojan_ClickerDelf_10
{
strings:
	$a0 = { 6f2f637269707365742f637269702e68746d6c00000000558bec33c055689b38 }

condition:
	$a0
}

        
