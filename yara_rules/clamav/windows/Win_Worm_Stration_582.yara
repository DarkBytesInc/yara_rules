rule Win_Worm_Stration_582
{
strings:
	$a0 = { eebf79134a7a7067118793928982899188e60b6ffe9bff2c2f363b3a2d32335f5f494c5e594e4b4c3bf1f4e3f6eeffbf }

condition:
	$a0
}

        
