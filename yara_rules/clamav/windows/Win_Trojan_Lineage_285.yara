rule Win_Trojan_Lineage_285
{
strings:
	$a0 = { 32a5660415050c65fc074aa1bbbf58df416576a1c88b7d8f7d45875da7435aa017b7a3341fa89baff903363a739845770324b7de26350f35cf9ad3ca7b97f3fdfed81e8340da59df58dcdf8b92657dfa07d74a2ad4af61d14efe9f63 }

condition:
	$a0
}

        
