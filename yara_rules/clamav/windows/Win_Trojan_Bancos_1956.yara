rule Win_Trojan_Bancos_1956
{
strings:
	$a0 = { 4fb07d09bee804201edbc38a3a3855c38d5d476df60d11f0ca7c427eb00e234a399a744abcd0ec47a092e051c75776cea527eb771f2d9ca54acf13e85d61119d7cf09f2928d7a64bca1893fd8f47b353bf9539cfb37b5bc57ea5 }

condition:
	$a0
}

        
