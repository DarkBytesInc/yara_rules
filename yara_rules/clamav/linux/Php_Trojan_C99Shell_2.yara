rule Php_Trojan_C99Shell_2
{
strings:
	$a0 = { 6578706c6f646528223a222c6667657473282466702c3230343829293b[1-8]696620286339396674706272757465636865636b28226c6f63616c686f7374222c32312c312c247374725b305d2c247374725b305d2c247374725b365d2c246671625f6f6e6c797769746873682929[3-18]6563686f20223c623e436f6e6e656374656420746f20222e }

condition:
	$a0
}

        