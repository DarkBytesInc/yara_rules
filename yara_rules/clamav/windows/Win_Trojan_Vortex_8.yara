rule Win_Trojan_Vortex_8
{
strings:
	$a0 = { fab8455992cd1650599292929292925d81ed060192925053929251529292565755061eb8cd7b9292cd2181fbcd7b }

condition:
	$a0
}

        
