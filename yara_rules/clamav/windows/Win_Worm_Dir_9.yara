rule Win_Worm_Dir_9
{
strings:
	$a0 = { 0133db8edbb384b87e0187072e898424018cc88747022e89842601fabc3d03fbb44abb4d03c1eb04cd210e1fbe80 }

condition:
	$a0
}

        
