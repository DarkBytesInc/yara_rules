rule Win_Spyware_54879_1
{
strings:
	$a0 = { 506804010000ff15043140008d85dcfcffff505768884240008d85e4feffff50ff15083140006860424000bb5442400053684c4240008d85e0fdffff508b3568314000ffd6 }

condition:
	$a0
}

        