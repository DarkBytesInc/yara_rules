rule Win_Worm_Deborm_10
{
strings:
	$a0 = { 8d45fc506a00683f000f006a006a006a0068082242006802000080ff15b8724200 }

condition:
	$a0
}

        
