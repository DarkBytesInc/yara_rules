rule Win_Trojan_CVE_2009_3518_1
{
strings:
	$a0 = { 69696d3a2f2f22202d766d20 }

condition:
	$a0
}

        
