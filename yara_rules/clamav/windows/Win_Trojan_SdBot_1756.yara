rule Win_Trojan_SdBot_1756
{
strings:
	$a0 = { c687a73a9b8ecc124f9226d72a99f1de37afa6e9cebbaaead2b07a27bbaf6cc37e5036579ba2a3a5dca88b7b05643cccd1ea144b102383f5b228c8fa42e7231dcdcb1273077149e93f57f1a86718b7d3c63328692a3bc4531e10682bf9abac97f8214e9ed64bc5ac }

condition:
	$a0
}

        
