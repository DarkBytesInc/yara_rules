rule Win_Trojan_Mybot_7233
{
strings:
	$a0 = { 669e17b95a6a790203f4a6a0834a34cbc177ae1a8699fc67af8f5d9f8306b21271549658da739f7db69dfb4f482c15a9f25fc89927bc9dcbd264c8a874edda3e4bb6236ca4341c30f01c00662dc0 }

condition:
	$a0
}

        
