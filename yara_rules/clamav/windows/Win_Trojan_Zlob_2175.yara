rule Win_Trojan_Zlob_2175
{
strings:
	$a0 = { 6a0aff15??404000506a006a00ff157??0400050e8????ffff50ff15??404000 }
	$a1 = { 74697665000000006365737361630000766964656f6163 }

condition:
	$a0 and $a1
}

        
