rule Win_Trojan_Alanche_1
{
strings:
	$a0 = { 417070656e642072616e646f6d20696e73756c7420746f206d6573736167650005980d38040f0f3b01ff }

condition:
	$a0
}

        
