rule Win_Worm_Alcaul_13
{
strings:
	$a0 = { 636f7061756c94fb3f593b0c3563233dfbfcfaa06810a73813485fc87e2b3371b5220f73c087efb7ff2f00794fad339966cf11b744aa0060d3931fdcc8dfbd }

condition:
	$a0
}

        
