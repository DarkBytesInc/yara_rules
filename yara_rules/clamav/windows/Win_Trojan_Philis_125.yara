rule Win_Trojan_Philis_125
{
strings:
	$a0 = { 570f02fe5f6056465ee800000000535790bb051d000081f7706800005f5b57565e5f464e5ab8fa000000 }

condition:
	$a0
}

        
