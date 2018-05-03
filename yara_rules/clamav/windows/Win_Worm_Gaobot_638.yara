rule Win_Worm_Gaobot_638
{
strings:
	$a0 = { 63764762699372eb84249d8e6c654156ae1a5a26306c462d0e41474f424f54e745582a540048494a41 }

condition:
	$a0
}

        
