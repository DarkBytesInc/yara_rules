rule Win_Worm_Koobface_33
{
strings:
	$a0 = { 687474703a2f2f25732f6361702f3f613d67657426693d256426763d3700 }

condition:
	$a0
}

        
