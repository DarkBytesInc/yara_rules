rule Win_Trojan_AntiTrace_3
{
strings:
	$a0 = { 0300fa0633c98ec15126c40e04002e898f49012e8c874b010726c7060400e90026011e0400268c0e060007fb2e }

condition:
	$a0
}

        
