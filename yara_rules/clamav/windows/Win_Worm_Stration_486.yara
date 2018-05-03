rule Win_Worm_Stration_486
{
strings:
	$a0 = { dc275f5279e8bcdeb739cf20ea706ed97359da1f6747019edf0b714372ca9f2eb6d87946a5d9c170dd733e2243e9fa76b3cdb37e5cf29d2cbb156442cc48e4cdcf4e0ad73ddf8c446c73a720a80a1c7fc57fc3671a5157467aaf6137 }

condition:
	$a0
}

        
