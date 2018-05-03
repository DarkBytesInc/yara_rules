rule Win_Worm_Deborm_2
{
strings:
	$a0 = { 6a00526a00683f000f006a006a006a0068307040006802000080ff1508604000 }

condition:
	$a0
}

        
