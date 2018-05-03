rule Win_Worm_Koobface_43
{
strings:
	$a0 = { 2573797374656d726f6f74255c73797374656d33325c737973646c6c2e657865 }
	$a1 = { 776562737276 }

condition:
	$a0 and $a1
}

        
