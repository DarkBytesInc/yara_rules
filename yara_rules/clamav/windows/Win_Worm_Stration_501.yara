rule Win_Worm_Stration_501
{
strings:
	$a0 = { 5c0000002e65786500 }
	$a1 = { ec34535657b90b000000be101040008d7c2410f3a5a433c08da4240000000080740410??4083f82c7cf568 }

condition:
	$a0 and $a1
}

        
