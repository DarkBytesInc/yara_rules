rule Win_Worm_Small_4609
{
strings:
	$a0 = { 77696e68656c702e657865 }
	$a1 = { 633a00005c[0-219]2e657865[0-30]5c43757272656e7456657273696f6e5c52756e }

condition:
	$a0 and $a1
}

        
