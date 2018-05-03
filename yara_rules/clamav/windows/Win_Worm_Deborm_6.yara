rule Win_Worm_Deborm_6
{
strings:
	$a0 = { 6a008d55fc526a00683f000f006a006a006a00681c2042006802000080ff15bc814200 }

condition:
	$a0
}

        
