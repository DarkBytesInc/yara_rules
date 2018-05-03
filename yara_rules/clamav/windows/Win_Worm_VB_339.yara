rule Win_Worm_VB_339
{
strings:
	$a0 = { c745fc0300000033d28d4db8ff1574114000baa0dc49008d4dbcff1574114000 }

condition:
	$a0
}

        
