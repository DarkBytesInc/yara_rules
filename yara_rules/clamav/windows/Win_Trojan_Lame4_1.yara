rule Win_Trojan_Lame4_1
{
strings:
	$a0 = { c706500000006a022eff16560074156a042eff1656006a012eff1656006a052eff1656006a0d2eff16560055538bec }

condition:
	$a0
}

        
