rule Win_Worm_Lasbat_1
{
strings:
	$a0 = { 6563686f2067657420302e6578653e3e363636776f726d }
	$a1 = { 322e657865202d6120246474202d78202d63 }

condition:
	$a0 and $a1
}

        
