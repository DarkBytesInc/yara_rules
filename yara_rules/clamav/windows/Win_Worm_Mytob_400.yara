rule Win_Worm_Mytob_400
{
strings:
	$a0 = { eb016860e8000000008b1c2483c312812be8b10600fe4bfd822c24acdf46000be4749e7501c7817304d77af72f81731977 }

condition:
	$a0
}

        
