rule Win_Trojan_Vortex_12
{
strings:
	$a0 = { fab8455992cd1650599292925d81ed060192925053929251529292565755061eb8cd7b9292cd2181fbcd7b929274 }

condition:
	$a0
}

        
