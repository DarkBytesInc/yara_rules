rule Win_Worm_Sobig_2
{
strings:
	$a0 = { 4d634db72010b7f5d8088dd1bda766618cc33b0daef8077c4791da11a304c16ad9c1dbe2f05b37 }

condition:
	$a0
}

        
