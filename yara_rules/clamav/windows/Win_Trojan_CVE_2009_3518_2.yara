rule Win_Trojan_CVE_2009_3518_2
{
strings:
	$a0 = { 69696d3a2f2f222532302d766d253230 }

condition:
	$a0
}

        
