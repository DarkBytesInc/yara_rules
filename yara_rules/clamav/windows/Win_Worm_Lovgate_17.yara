rule Win_Worm_Lovgate_17
{
strings:
	$a0 = { 373321a769a7ec7fb4480146deda662a3c23e5cb1b9387e552a62db9f7897485dc78cdd97ec070bb26a51ef92d9d140fdc930bdb08e6e198f54841160d7ca599 }

condition:
	$a0
}

        
