rule Win_Trojan_Agent_35237
{
strings:
	$a0 = { a46fbf3b608dc38385a21a094af359466b5ccc8f2e178d6e8794cf6dddf0ad2c8d60c78428b81ede5a24360737ff0400a061a40c1b7eb8ad3d7a97187c33395fa14eccedb3b6a23b909b05fd6ab7601ac79f18e09cc5 }

condition:
	$a0
}

        
