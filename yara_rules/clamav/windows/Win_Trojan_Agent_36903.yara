rule Win_Trojan_Agent_36903
{
strings:
	$a0 = { 443a5c73656e74656e6365616d6f6e675c61726561737461725c48656265642e706462 }

condition:
	$a0
}

        
