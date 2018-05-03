rule Html_Trojan_ClickerSmall_118
{
strings:
	$a0 = { 68fc5040006a008bf06a0c56ff15cc5040008b3dd05040006a006a006a0756ffd76a006a0d680001000056ffd7 }

condition:
	$a0
}

        
