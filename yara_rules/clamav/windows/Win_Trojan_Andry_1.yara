rule Win_Trojan_Andry_1
{
strings:
	$a0 = { 368b1c5aba03012bdaeb0490f873ec8beb83fd007406909090eb0190e93801546869732076697275732077617320 }

condition:
	$a0
}

        
