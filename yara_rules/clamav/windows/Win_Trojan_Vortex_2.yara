rule Win_Trojan_Vortex_2
{
strings:
	$a0 = { 01fab8455992cd1650599292925d81ed0601929250539292515292925657929255061eb8cd7b9292cd2181fbcd7b92 }

condition:
	$a0
}

        
