rule Win_Dropper_Agent_35554
{
strings:
	$a0 = { e821feffff8d45ecba80464000b905010000e8affaffff8d45ecba20214000e8c2faffff8b55ecb834214000e855feffff08c0742f6a018d45e8ba80464000b905010000e87dfaffff8d45e8ba20214000e890faffff8b45e8e8dcfaffff50e8e2fdffff }

condition:
	$a0
}

        
