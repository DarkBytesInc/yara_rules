rule Win_Trojan_Lineage_514
{
strings:
	$a0 = { d55a1941877a36a9cac10a8ff43f46aa9e5de775e4034dca9e4e0a578058c01a51f22e98156f817fc8525467338b0ade1b070cef6428f8508b3cef4b5dbc05b8efa83e24457c12a16bff1d8e253919021d8d513a25eb9fa6acfaf853 }

condition:
	$a0
}

        
