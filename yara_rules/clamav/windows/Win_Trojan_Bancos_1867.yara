rule Win_Trojan_Bancos_1867
{
strings:
	$a0 = { 4f82faf7cf1cc373a5e7ff93d25e05fc9d57958ed701085675ba1b714709d785c0dd36f3c9e5f7316d0dd53114985df82a044aac621b2ed5a86589963a3b6901c333ad130dc7 }

condition:
	$a0
}

        
