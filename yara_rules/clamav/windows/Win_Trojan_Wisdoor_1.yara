rule Win_Trojan_Wisdoor_1
{
strings:
	$a0 = { f9ce6a9d0f6a414b095ac73b8f8ec7bb10f94a6a273acb665fddbc27ce2ffc56fff4747a81f4fd40e824db2228f4d3dd3326b83d44e8b15d700acfde5b8a7982fb12bfcb77b61ea67bb12743cd19e039c32cb9a4f01f5bfe0e4b1a2186951d02a1f31fea06cdd3efd216 }

condition:
	$a0
}

        
