rule Win_Worm_VBS_213
{
strings:
	$a0 = { 7428226f75746c6f6f6b2e6170706c69636174696f6e2229 }
	$a1 = { 226d61706922 }
	$a2 = { 7373656e74726965732e636f756e74 }
	$a3 = { 6174746163686d656e7473 }
	$a4 = { 2e616464 }
	$a5 = { 2e73656e64 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}

        
