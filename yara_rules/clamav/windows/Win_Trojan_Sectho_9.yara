rule Win_Trojan_Sectho_9
{
strings:
	$a0 = { 756768742e636f6d002f76372f636c2e7068703f613d6526623d256426633d2564000000002f76372f636c2e7068703f613d6326623d2564006f70656e000000002f76372f646174612f77696e757064742e65 }

condition:
	$a0
}

        