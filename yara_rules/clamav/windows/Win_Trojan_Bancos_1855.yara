rule Win_Trojan_Bancos_1855
{
strings:
	$a0 = { c3ce414d09689841a9c37cb6a6df8063af6741dd917cbef26f77975ad07b71a6d0586e584d0ae12c1f3f21056a0a35d7fcfcd75ed31022ac7de598541006210b1d2a56c3e047 }

condition:
	$a0
}

        
