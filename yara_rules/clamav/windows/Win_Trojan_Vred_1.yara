rule Win_Trojan_Vred_1
{
strings:
	$a0 = { 6f70656e20222e5c2a2e77687322[0-44]66696e6420227672656465736279726422 }

condition:
	$a0
}

        
