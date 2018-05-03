rule Win_Worm_Stration_657
{
strings:
	$a0 = { 37cf9bb3d99e202e6578655c362669bffcfff96e7526361b5c796d687d6c297a7c6a6a6c6f7c656570f7ffbf }

condition:
	$a0
}

        
