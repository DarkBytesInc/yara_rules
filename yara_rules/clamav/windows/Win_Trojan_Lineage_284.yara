rule Win_Trojan_Lineage_284
{
strings:
	$a0 = { 899509506aa5293929adaa85bd6efe7b4b99133f0310a318f2f83410eac80c55efa1e8eead09812684d12d05aa1b45961ec9bb917aae76437835f88a7de00a710da024e52b332a2fa91c2c7a188aafbf1554c8a4b004a3a6654eff5e }

condition:
	$a0
}

        
