rule Win_Worm_Zimuse_1
{
strings:
	$a0 = { 6175746f72756e2e696e66 }
	$a1 = { 746f6b7365742e646c6c }
	$a2 = { 4d5345552e535953 }

condition:
	$a0 and $a1 and $a2
}

        
