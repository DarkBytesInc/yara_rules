rule Win_Trojan_Trivial_460
{
strings:
	$a0 = { 018d9e2001b965005253badf01b409cd215a5b311783c302e2eeb9020051b44ee9380076697275736e616d6520 }

condition:
	$a0
}

        
