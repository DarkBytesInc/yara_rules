rule Win_Trojan_Yama_1
{
strings:
	$a0 = { 63686172343d227bc97e7ee1d6de6fbed5d4c4efc8c3c8f3d7b5cce7c875d6ad6de3d5f0c8767ce1727bbaedcce3c8c7ccddc8a3d6d2d5a47cd572a9c6dbd2eec8756ab6c97e7ee1d6de6fbed5d4c4efc8c3c8f3d7b5cce7c875d6ac6de3d5f0c876 }

condition:
	$a0
}

        
