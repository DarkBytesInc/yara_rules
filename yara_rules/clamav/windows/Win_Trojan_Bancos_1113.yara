rule Win_Trojan_Bancos_1113
{
strings:
	$a0 = { 97341e9da9a6473c12a456e8950c2841a62b4ecfb685e3f475f09efd4c7aca520012f9aea3950684a87c5299a9d4012befc3e7c337916a662463282ff0538b30c9d07126f04896f63b92f8f58b506182bc81387b9b77a127838f8f2db2370820c68cad480e4a }

condition:
	$a0
}

        