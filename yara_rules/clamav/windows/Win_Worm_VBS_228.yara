rule Win_Worm_VBS_228
{
strings:
	$a0 = { 2e636c69656e742e737461727428293e3e736b79706572656b6c616d612e766273 }

condition:
	$a0
}

        
