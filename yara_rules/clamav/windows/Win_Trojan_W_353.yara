rule Win_Trojan_W_353
{
strings:
	$a0 = { c1c8146681384d5a74112d001000004975f15d81ed19144000f9c3508b403c5e66813c065045 }

condition:
	$a0
}

        
