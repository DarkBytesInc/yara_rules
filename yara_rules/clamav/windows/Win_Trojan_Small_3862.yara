rule Win_Trojan_Small_3862
{
strings:
	$a0 = { 32d253ea739ccbc7339ce3ad0ad163c5b6607c8ef6efba50afc073f80ed85e3b37ce23b160d5823955f2ee8cbe9363f6321188d91b469ec533f5e8858c116f48f9a0a650f91fa2c5a880c2486f3b64d4c85cc320f6f2ba50af }

condition:
	$a0
}

        
