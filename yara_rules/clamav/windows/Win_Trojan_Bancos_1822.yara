rule Win_Trojan_Bancos_1822
{
strings:
	$a0 = { 831908638e1783d5e8baf80e77108cf0cb1a6ec0c24d0c4e44d2e2c94a67624c06595be5680ce92bf0c452de3ee0826336a38528baa12922385adbcb20e485e4241ed2e7539b }

condition:
	$a0
}

        
