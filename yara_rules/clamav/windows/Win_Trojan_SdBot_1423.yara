rule Win_Trojan_SdBot_1423
{
strings:
	$a0 = { 235ef9e5def7f17fb6a59690ebb899a312f65f83335797e1c1ae5b14c3a8c05c6a4fbcbcf1cb16de4821d5d5d07532ffd03f7431dca75f2502cdebb1ca6fb68dd6f8802676a013680d02f1e789dcb28bd24e84a16baef4b861fe2748e2a3b8f5fc6b11c4 }

condition:
	$a0
}

        
