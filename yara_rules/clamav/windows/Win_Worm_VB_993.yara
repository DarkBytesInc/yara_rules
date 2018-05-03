rule Win_Worm_VB_993
{
strings:
	$a0 = { 6810244000e8f0ffffff0000000000003000000038 }
	$a1 = { 5cff58ff54ff50ff4cff48ff44ff40ff3c }

condition:
	$a0 and $a1
}

        
