rule Win_Trojan_Fakecodec_7
{
strings:
	$a0 = { ffff314dd0198d24feffffff850cffffff0185dcfeffff31c881e8001e000031c80b856cffffff31c00b8508ffffff1185fcfdffff0985bcfeffff0345c03345c0ff8df8feffff218530feffffff45ccff75d0ffb5b0feffff68000100006a006affff15 }

condition:
	$a0
}

        
