rule Win_Trojan_Fakeav_40
{
strings:
	$a0 = { 8d0596e9950189188d051ee99501505b8933578f052ae99501528f05b9ea9501891d40d0950188 }

condition:
	$a0
}

        
