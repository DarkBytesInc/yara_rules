rule Win_Trojan_Mypis_2
{
strings:
	$a0 = { 558bec83c4ec5356578d75fceb01e8909090909090eb01e89090eb0f81384d5a900074122d00100000ebf18b442414250000ffffebe68945fce8b6ffffff2dc50000008945f48b068b }

condition:
	$a0
}

        