rule Win_Trojan_Spambot_151
{
strings:
	$a0 = { 5ee5ff7f8afa0ebe9cf6924593e7e866a139fd905a7ed9ffffffffdf66969847dbec965a57dd937e5a368a1dd9a19023d53e83dd0c5e35e957c1b3ff1ffdffff23d2d9efadcda157f8303dbd1eab21fd45f4ae65ded985c83afffffffff43a97849d170a2295f4076a0be5dd53c7 }

condition:
	$a0
}

        
