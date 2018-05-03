rule Email_Trojan_E_card_7
{
strings:
	$a0 = { 636f7079202620706173746520697420696e746f20796f75722062726f77736572 }
	$a1 = { 687474703a2f2f39 }

condition:
	$a0 and $a1
}

        
