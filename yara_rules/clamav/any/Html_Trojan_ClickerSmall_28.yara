rule Html_Trojan_ClickerSmall_28
{
strings:
	$a0 = { 652e6e65742f322e68746d6c000000005c4953546261725c6973746261722e646c6c00005c495354737663005c4953547376635c6973747376632e6578 }

condition:
	$a0
}

        