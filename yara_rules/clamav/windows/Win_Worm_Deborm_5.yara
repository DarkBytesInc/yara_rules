rule Win_Worm_Deborm_5
{
strings:
	$a0 = { 6a008d55fc526a00683f000f006a006a006a0068c81142006802000080ff1558624200 }

condition:
	$a0
}

        
