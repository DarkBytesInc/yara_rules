rule Doc_Trojan_Zed_3
{
strings:
	$a0 = { 566972757350[0-73]484b45595f435552[0-70]5c53656375726974[0-52]65737356424f4d22 }

condition:
	$a0
}

        
