rule Win_Trojan_Nocwage_1
{
strings:
	$a0 = { 83c40c6a108b45cc506a006a248d45a4508b45fc50e8e1fbffff83c41889c083f8ff751768c48b0408e88dfbffff83c4046a01e823fcffff }
	$a1 = { 6f0041747461636b20616761696e7374202573206669 }

condition:
	$a0 and $a1
}

        
