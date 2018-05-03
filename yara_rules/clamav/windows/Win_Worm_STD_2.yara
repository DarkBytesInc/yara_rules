rule Win_Worm_STD_2
{
strings:
	$a0 = { 3d202f2e636f707920433a5c77696e646f77735c73797374656d5c72756e }

condition:
	$a0
}

        
