rule Win_Trojan_KillFiles_30
{
strings:
	$a0 = { 22696620657869737420633a5c77696e646f77735c242e2420676f746f2061766c6973745f22207072696e742023322c2022696620657869737420633a5c77696e646f77735c686f73747320676f746f20397861763122207072696e74202332 }

condition:
	$a0
}

        