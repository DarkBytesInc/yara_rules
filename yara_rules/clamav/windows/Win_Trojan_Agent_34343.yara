rule Win_Trojan_Agent_34343
{
strings:
	$a0 = { 50515958595883c4f0595883ec0450515958595883c4f05958c7042425401813 }

condition:
	$a0
}

        
