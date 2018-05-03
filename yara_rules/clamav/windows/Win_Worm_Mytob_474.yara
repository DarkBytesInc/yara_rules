rule Win_Worm_Mytob_474
{
strings:
	$a0 = { 558bec81ec70050000e8c8020000e82a00000068700500008d85 }
	$a1 = { 6f70656e3d[0-4]766f6c756d652e657865 }

condition:
	$a0 and $a1
}

        
