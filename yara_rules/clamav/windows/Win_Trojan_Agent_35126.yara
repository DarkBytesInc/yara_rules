rule Win_Trojan_Agent_35126
{
strings:
	$a0 = { c14290f50174532a7abfd1a34c749c025740cd009fab78cffb029a13835fb8fa9378b061e20a13a02c45a980071d1081b350d0060bc2a0de7b360d23e80e9f3e49fba42f8b85a7a463dbdad4bed3ff1b }

condition:
	$a0
}

        
