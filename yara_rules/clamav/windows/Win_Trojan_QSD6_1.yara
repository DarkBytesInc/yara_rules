rule Win_Trojan_QSD6_1
{
strings:
	$a0 = { 12005589e5c7064000ffffbf00000e579abb0612009a0e021200a1400040a34000a1400040a33e00a140009952 }

condition:
	$a0
}

        
