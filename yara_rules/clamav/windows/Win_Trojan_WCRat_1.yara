rule Win_Trojan_WCRat_1
{
strings:
	$a0 = { ffffe8b3fcfcffe85b0afdffe8cde6fcff8d8534feffffe8720afdffe8bde6fcff33c05a595964891068044043008d4508e8d0f6fcffc3e9eaf0fcffebf08be55dc204000000ffffffff12000000633a5c77696e646f77735c6b65792e6c6f670000ffffffff050000005370616365 }

condition:
	$a0
}

        
