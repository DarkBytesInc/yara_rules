rule Win_Trojan_Agent_33068
{
strings:
	$a0 = { ff03952c901bb46c4e8f08024a18f414535790900cfa9a36182394ac40ffff5f6274856ac1db08bbcb48152067d0b94169f7da7aad30c2edffffff1bd26108600b12b370fb9d782c85d2 }

condition:
	$a0
}

        
