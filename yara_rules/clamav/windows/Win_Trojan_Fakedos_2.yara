rule Win_Trojan_Fakedos_2
{
strings:
	$a0 = { 8b45f05068cc96420068c89642006870624200e8c4c5ffff83c41085c075168bf468e8030000ff1584c442003bf4e8d3060000ebcb }

condition:
	$a0
}

        
