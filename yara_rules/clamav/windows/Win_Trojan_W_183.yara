rule Win_Trojan_W_183
{
strings:
	$a0 = { e8000000005e83ee05a1e88ffbbf3d146c0000750cc786b5060000146cf7bfeb4ca1f405fcbf3d186c0000750cc786b5060000186cf7bfeb34a1fc05fcbf3d5c6d0000750cc786b50600005c6df7bfeb }

condition:
	$a0
}

        
