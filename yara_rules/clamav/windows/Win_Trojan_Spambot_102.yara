rule Win_Trojan_Spambot_102
{
strings:
	$a0 = { 7ef34ef71135892c47ff3ffc980a848e1fa28bf3bf09dbdd7026004b08b0e952f0fffffff893f859a1e7844b80cc264fe86c712c2ebdab6a487d837933813beeffffff9fe3d8e657d7e57a3669fa7d2c297d8b21db8a22a052910e02b5bd517f3cc0ff230ab90e16a66c937d9523 }

condition:
	$a0
}

        
