rule Win_Trojan_RIPPER_1
{
strings:
	$a0 = { f8c3f9c3505351523a16770188167701751333c0cd1a8bc22b067501891675013d360072075a }

condition:
	$a0
}

        
