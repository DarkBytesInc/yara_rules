rule Win_Trojan_SdBot_4022
{
strings:
	$a0 = { 854c7705e9084c1437f80dc1767bec04a5fbe6fc03eb006fd6d26c5544800e7c40402078fd88716ed6435ba5a65f41ba124ee45aa1de969ba89778d3488e4db39ed38d7dcc5cb4bb0028b8dc1afcdb490fa68cf43653 }

condition:
	$a0
}

        
