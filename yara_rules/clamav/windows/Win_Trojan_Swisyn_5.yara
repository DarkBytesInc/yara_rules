rule Win_Trojan_Swisyn_5
{
strings:
	$a0 = { 6820644000e8f0ffffff00000000000030000000380000000000000015ac999260c70048a53a08023a3bb80500000000000001000000000000000000737663686f73740000000000ffcc310001aac9cececb6fc34db7d6e537dfadb928aa2a9924f7a74e458f9959146217916a3a4fad339966cf11b70c00aa0060d393000000 }

condition:
	$a0
}

        