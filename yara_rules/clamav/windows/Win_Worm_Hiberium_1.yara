rule Win_Worm_Hiberium_1
{
strings:
	$a0 = { 486962657269756d }
	$a1 = { 5c43757272656e7456657273696f6e5c52756e }

condition:
	$a0 and $a1
}

        
