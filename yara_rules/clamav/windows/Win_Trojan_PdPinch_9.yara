rule Win_Trojan_PdPinch_9
{
strings:
	$a0 = { ae0aaac958fec9558f7bc75beab0eeb1eabafb0efeac5f7558b5c6b592b9ff9ff3d77df07f967ef3df405faadd1674b3547208564d66723de3d21c64d4d026e55be6abe3bd4c33fec6e186ab15e4d46f5f3788f51c1c160173323d5c2a2b8855f49910fe0d808b7e006bb55b67cc513a1b2ef7762cab4cddce73969ea4f80a6a26680aa1fc2e1a05ace37884 }

condition:
	$a0
}

        