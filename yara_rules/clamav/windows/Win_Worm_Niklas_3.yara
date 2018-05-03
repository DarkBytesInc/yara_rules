rule Win_Worm_Niklas_3
{
strings:
	$a0 = { 8d45fce8d7eeffff8d45b0b9505440008b55fce877d1ffff8b45b0e87ff0ffff84c074188d45acb9505440008b55fce85bd1ffff8b45ace8f7faffff }

condition:
	$a0
}

        
