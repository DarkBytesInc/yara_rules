rule Win_Trojan_Sdbot_44
{
strings:
	$a0 = { da1ad330364c093f3a3ea7fb59d04ba2e14c4a2f046e2f79a5cf88331a8b73c19339a1cb4c0efe44f1f01bbda7c627c715be4080e44d0850cfba94dbc2900f9b7a8d77bbc02fed047bbcde073767484e2379f7bdfccfa5d1588f7144bd70e390b7c1a22b6a5c8ec18d218ae5cffa10d73be5a500171ff4 }

condition:
	$a0
}

        
