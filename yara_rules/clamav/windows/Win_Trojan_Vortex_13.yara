rule Win_Trojan_Vortex_13
{
strings:
	$a0 = { fab8455992cd1650599292925d81ed0601929292925053929251529292565755061eb8cd7b9292cd2181fbcd7b92 }

condition:
	$a0
}

        
