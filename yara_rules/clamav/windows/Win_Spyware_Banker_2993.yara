rule Win_Spyware_Banker_2993
{
strings:
	$a0 = { 79f51c13d503f29f0d41b4ef15ba5e528d189c5f62f341d02fd832fc476ea87b09a3e083b5f2d09dfc2fc1f2da3e40a2fbc7d942b229fbb9952b41d6d40c94d7deb8f701d6d84519caef5417538b591baeabe29001c7ce71746726385edc8016dab6dfd0 }

condition:
	$a0
}

        
