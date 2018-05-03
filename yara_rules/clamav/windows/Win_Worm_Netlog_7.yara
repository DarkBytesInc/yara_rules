rule Win_Worm_Netlog_7
{
strings:
	$a0 = { 22633a5c77696e646f77735c6e69672e76627322 }
	$a1 = { 737461727475705c6e6574776f726b2e766273 }

condition:
	$a0 and $a1
}

        
