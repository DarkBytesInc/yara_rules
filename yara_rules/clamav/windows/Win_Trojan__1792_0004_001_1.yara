rule Win_Trojan__1792_0004_001_1
{
strings:
	$a0 = { 33c9b80042cd21b91c00baa102b440cd21e924ff5b4245415649535d206279204372797074 }

condition:
	$a0
}

        
