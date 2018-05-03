rule Win_Worm_Locksky_31
{
strings:
	$a0 = { 0f6fe0e8080000000fd9c8e827000000 }

condition:
	$a0
}

        
