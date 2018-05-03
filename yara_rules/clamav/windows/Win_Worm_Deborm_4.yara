rule Win_Worm_Deborm_4
{
strings:
	$a0 = { 6a008d55fc526a00683f000f006a006a006a0068080142006802000080ff15e85142003bf4e8c7000000 }

condition:
	$a0
}

        
