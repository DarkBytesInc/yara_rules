rule Win_Worm_GaobotHL_1
{
strings:
	$a0 = { 8616b971c4f8ddedaa6425b2ddba6ec4c426b73b3ee4629cde1cd6d2dfd36ba51c7be9efb563d4b29f8d6fd219959d7c85e2533508a95c9d2b791a795627a40439004a7d5a7b3d59fa22335bfaeffe213c1f146e }

condition:
	$a0
}

        
