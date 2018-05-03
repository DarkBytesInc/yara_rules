rule Win_Worm_LovGate_5
{
strings:
	$a0 = { c0d799ab03b1518c7db0ecc5f391a76d3ee9c1df108e9fbdded10949614d45e16b1fbebacf09b0ea }

condition:
	$a0
}

        
