rule Win_Trojan_Bancos_1751
{
strings:
	$a0 = { 0e9b3198fbb2dcc2c09c90e204b1e6470c53771223704ae482af743c7bf18ec7071b380c4437a8d9932370d94ccffb81ac4db4a5a98548083451d031f1eb23e8ed4147698359 }

condition:
	$a0
}

        