rule Win_Trojan_Delf_1275
{
strings:
	$a0 = { 50802920454105191f1462021c022739207083b9b5aaee5ccb7737b9afe1dfc077b99dc816f77206dbdde41b77606db5e45b460bdabc905a401baf602db80376e4836b906bd7202db905adce40572017ae4071cc83777720b77b906d6e037bb9976e677bfffffedf7fbd7af7efcf3e7cf7f3cf7f3cf9e739fb7afbfa0cb18201262fd92c963b0d7f7d2243e6 }

condition:
	$a0
}

        