rule Win_Trojan_Spambot_188
{
strings:
	$a0 = { 883ee67008ffffffff4605b55b2622671b814bb4a4d06ff0793c6c956a7037a1c6beed6db8688543f3ffffffffae9de4e2a3dcd9b9289f8080d4c71baeca7a96db413b9fc75c25d4c0889903f9fdffffffd15fa0f4a1cb8e5a39df057b545f33e405a14053b1cd041d8b329ddd69 }

condition:
	$a0
}

        
