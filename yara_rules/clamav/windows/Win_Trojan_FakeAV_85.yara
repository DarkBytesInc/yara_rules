rule Win_Trojan_FakeAV_85
{
strings:
	$a0 = { 558bec6aff68e00151006880614e0064a100000000506489250000000083ec585356578965 }

condition:
	$a0
}

        
