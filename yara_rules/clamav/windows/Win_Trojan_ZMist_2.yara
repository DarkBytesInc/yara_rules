rule Win_Trojan_ZMist_2
{
strings:
	$a0 = { b00fe8fb0f0000ffd096b420ac3c227502b422ac0ac00f84b60000003ac475f35668987740006866f3a52ce8d20f0000ffd0685876400068987740006844244332e8bc0f0000ffd083f8ff0f848100000083ec248bec68000800006a006871a15e72e89b0f0000ffd00bc0746589450868000008006a006871a15e }

condition:
	$a0
}

        