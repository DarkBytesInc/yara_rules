rule Win_Spyware_Banker_2791
{
strings:
	$a0 = { f6b8cdf289bc4ea5dbc8aec3ee836e37cceb2d9d237d3818ef6b222c4657f772534ebe4f5b37bece24d7d7446e349eda542b5d7ad6a4c6a5cedb0089808c10657f2eaecd971622e1442951b94c75f0ab6ba8b0a91f4ba06160d9f6fb6cf832e3add95e23 }

condition:
	$a0
}

        
