rule Win_Trojan_Forbot_12
{
strings:
	$a0 = { 1e218139b3e65ffba3f417dfe65636499fe8bafb755e08b6cffcb2ac9cd23fba0a0978d38eb1cd48cf9ef92f17fcbff14d9c33388da1b282dc527653d26a6c0e7f432c14acdd71ee46af17391c93e2c233c900f422e0f6cacdb4f15d408f4e2215f1ceacaa067deff84c85e55293eed8f51f004bc929dd5286ba58 }

condition:
	$a0
}

        
