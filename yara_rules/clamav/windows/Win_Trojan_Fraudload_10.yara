rule Win_Trojan_Fraudload_10
{
strings:
	$a0 = { 82baffffffbbcd2ff0ffff3b422bc547073a86faffff11c56b80ffff1d3a6af8ffffffcdb780ffffdd5ce2ffffffe2735809e2ffff06e22ef71ae2ffffff81fdffffdefbffff2c6c66bfe2ffff0de286f619e284f6fcebfdffe78565f7e7e2376abfeafd }

condition:
	$a0
}

        
