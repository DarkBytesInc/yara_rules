rule Win_Trojan_Mybot_5707
{
strings:
	$a0 = { fffed9ba27f02f6330ff0f5522f499857096fffd7d8370bf157d20f1517536ed2ff570f296ff87c47881dfea2b93e233dce85f2e00b22690ff5be390bf860bca54e128c228ef7fe552a9de5f76c53bb3be24e149756c05c6fffc }

condition:
	$a0
}

        
