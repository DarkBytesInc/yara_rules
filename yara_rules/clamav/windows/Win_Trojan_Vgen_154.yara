rule Win_Trojan_Vgen_154
{
strings:
	$a0 = { ec33c05033d25052b8050050b8020050e8000083c40acd195dc3558bec83ec2456b8010050ff7604e8000083c404 }

condition:
	$a0
}

        
