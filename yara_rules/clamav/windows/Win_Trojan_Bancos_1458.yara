rule Win_Trojan_Bancos_1458
{
strings:
	$a0 = { d4452da880f892d5633a10831ad16a96914d43fb9ef01876ce1940709576bb112ec55ebbf4c5d5655c726b454d8bd3be13cabbbd1eebb930a29264cb5adeeb7f644d9509a6d32c45281ce98aa46dece7aca6b749f7810f4f224e }

condition:
	$a0
}

        
