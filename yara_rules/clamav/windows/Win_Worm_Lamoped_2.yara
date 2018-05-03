rule Win_Worm_Lamoped_2
{
strings:
	$a0 = { 3d2f6463632073656e6420246e69636b20222226 }
	$a1 = { 2622225c426574726179616c2e7662732222 }

condition:
	$a0 and $a1
}

        
