rule Win_Trojan_VGEN_461
{
strings:
	$a0 = { 7507c6050000000001b821000000be00000000cd2041000100f8c3807d1d4b741d807d1d3c7417 }

condition:
	$a0
}

        
