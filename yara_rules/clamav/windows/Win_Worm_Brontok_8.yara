rule Win_Worm_Brontok_8
{
strings:
	$a0 = { 06234c287f83ffff0d0a234a6f776f426f742d564d2043856d756e697479ec6d706816df8b670807d0debdc028372e3001 }

condition:
	$a0
}

        
