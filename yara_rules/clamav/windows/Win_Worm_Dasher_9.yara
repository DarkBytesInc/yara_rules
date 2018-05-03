rule Win_Worm_Dasher_9
{
strings:
	$a0 = { 741468842b4000e8140300006a00e8e9020000 }

condition:
	$a0
}

        
