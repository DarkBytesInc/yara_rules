rule Email_Trojan_Trojan_633
{
strings:
	$a0 = { 436865636b207468617420796f7572206769726c667269656e642073656e74206d65 }

condition:
	$a0
}

        
