rule Win_Adware_Webhancer_11
{
strings:
	$a0 = { 726f6772616d735c77656268646c6c2e646c6c0000002d696e7374616c6c000000002d727265636f7264 }

condition:
	$a0
}

        
