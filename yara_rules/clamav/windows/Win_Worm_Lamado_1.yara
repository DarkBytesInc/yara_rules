rule Win_Worm_Lamado_1
{
strings:
	$a0 = { 0fbfc885c9742dc745fc5d000000c785d4fcffffbc404000c785ccfcffff080000008d95ccfcffff8d8d50feffffff15b8104000 }

condition:
	$a0
}

        
