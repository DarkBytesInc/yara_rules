rule Win_Trojan_Loda_1
{
strings:
	$a0 = { 686b65795f6c6f63616c5f6d616368696e655c[0-63]22633a5c77696e646f77735c74726f79616e2e76627322 }

condition:
	$a0
}

        
