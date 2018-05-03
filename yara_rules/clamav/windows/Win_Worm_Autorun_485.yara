rule Win_Worm_Autorun_485
{
strings:
	$a0 = { 6c6465722830292b225c5c73797374656d33325c5c77696e7838362e646c6c2e6a7322 }

condition:
	$a0
}

        
