rule Win_Worm_QiMiral_2
{
strings:
	$a0 = { 558bec83c4f0b89cb94a00e808acf5ffa174ff4a008b00e8e0c4faffa174ff4a008b00baf4bd4a00e8c7c0faff8b0df8fd4a00a174ff4a008b008b15e85c4a00e8cfc4faffa174ff4a008b00e843c5faffe8b286f5ff0000ffffffff0400000048314e310000000000000000 }

condition:
	$a0
}

        
