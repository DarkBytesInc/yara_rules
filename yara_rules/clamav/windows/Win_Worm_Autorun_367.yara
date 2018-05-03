rule Win_Worm_Autorun_367
{
strings:
	$a0 = { 7368656c6c657865637574653d70726f6772616d2e6578652065 }

condition:
	$a0
}

        
