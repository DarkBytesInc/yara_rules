rule Win_Trojan_Agent_36960
{
strings:
	$a0 = { 737461727420633a5c77696e646f77735c312e6a70670d0a737461727420633a5c77696e646f77735c312e657865 }

condition:
	$a0
}

        