rule Win_Worm_Delf_1417
{
strings:
	$a0 = { 8b45fce824f9ffff33c9bab4cd40008b45fce8a9f9ffffbaf8cd40008b45fce8fcfcffff84c07424baf8cd40008b45fce8dffbffff487426b901000000baf8cd40008b45fce8b6fbffffeb12 }

condition:
	$a0
}

        
