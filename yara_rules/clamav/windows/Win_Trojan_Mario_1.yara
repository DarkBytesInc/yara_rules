rule Win_Trojan_Mario_1
{
strings:
	$a0 = { 40b99502ba00009c2eff1e1100b89502030645000306250033d2bb0002f7f38916250001062700 }

condition:
	$a0
}

        
