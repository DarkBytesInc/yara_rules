rule Win_Trojan_Bancos_1775
{
strings:
	$a0 = { ad96d081205d6f902323c13a971dbfec1b42465414a3b67b3289a360988d22f67277f5dd7442756647c212dca66da77a5d4b66715754d8f58f1c1d5ac053c8d5fcf42ad94dce }

condition:
	$a0
}

        
