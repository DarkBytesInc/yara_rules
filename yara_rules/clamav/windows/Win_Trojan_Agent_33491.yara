rule Win_Trojan_Agent_33491
{
strings:
	$a0 = { 724fb1b7770f3cdc48f2edc4d06f46270e3070b506bc4f91cad2b56c9b0e2f7ce6a46fbf3b608dc38385a21a094af359466b5ccc8f2e178d6e8794cf6dddf0ad2c8d60c78428b81ede5a24360737ff0400a061a40c1b }

condition:
	$a0
}

        
