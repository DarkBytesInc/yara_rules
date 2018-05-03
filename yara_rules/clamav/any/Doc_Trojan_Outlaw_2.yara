rule Doc_Trojan_Outlaw_2
{
strings:
	$a0 = { 8e08000400ffffb6350000d6030000030000000903 }

condition:
	$a0
}

        
