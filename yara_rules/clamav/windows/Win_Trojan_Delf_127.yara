rule Win_Trojan_Delf_127
{
strings:
	$a0 = { 311aa7e3e5d133f60c721d4881306d6f6e47d7e9e0737973051e6391ba6579d740ca75769ebaceefe96b0173706a2e65786528ef3a1f670e83eb6d03400beabd7669 }

condition:
	$a0
}

        
