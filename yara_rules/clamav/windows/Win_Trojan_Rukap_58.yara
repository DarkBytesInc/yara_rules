rule Win_Trojan_Rukap_58
{
strings:
	$a0 = { 474475e50322e0514063bbf1d38dd1267aa81f8b8d1395dfc3be587435237e27414440eb39ed968e155ada9e646ea96371ad73bbb0306b204c04a1c256d27f6e7fa60c37a41dd8b4 }

condition:
	$a0
}

        
