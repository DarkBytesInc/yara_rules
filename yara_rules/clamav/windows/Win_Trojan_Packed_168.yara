rule Win_Trojan_Packed_168
{
strings:
	$a0 = { 5781ec00020000545f680001000057e8????00008d577c33c951515152515703f8b85c6d6369abb877617665abb82e64 }

condition:
	$a0
}

        
