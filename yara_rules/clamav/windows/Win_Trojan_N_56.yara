rule Win_Trojan_N_56
{
strings:
	$a0 = { 0174043c0475318b4c028a7401e812017226803e7502ab741f5152e8ef00b408cd1388367e0089 }

condition:
	$a0
}

        
