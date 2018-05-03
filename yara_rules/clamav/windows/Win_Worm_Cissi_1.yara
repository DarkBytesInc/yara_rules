rule Win_Worm_Cissi_1
{
strings:
	$a0 = { 48454c4f203730585893e30bcdc8ffdd0b134d41494c2046524f4d3a200952d89bc3fe43505420544f3a3f064441544137cedeff730c6573 }

condition:
	$a0
}

        
