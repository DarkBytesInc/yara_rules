rule Win_Trojan_Qooloc_12
{
strings:
	$a0 = { fb570e10b5c41186834ff30a24ad5a0ee23f6a313ec9b49f3c7918e21f4b68beba4301b6ea4b113d6846b973e24a3f2ae6e84d2205fba49e6d2b668b67d95cdc7e642241591e0662336c2594500e8c303e37ea3487a23f48d47127cc1a266dd9d8e7d7c1e3be33af770df2905acf17546dde85f3df51d7939e2006 }

condition:
	$a0
}

        