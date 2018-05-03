rule Win_Worm_Pinit_3
{
strings:
	$a0 = { 6081cb775f8bdd8d1d28540b378bdac1d1048d0d1dfd4f2d33d14e47[0-68]682e646c6c }
	$a1 = { 4da05d686b65726e }

condition:
	$a0 and $a1
}

        
