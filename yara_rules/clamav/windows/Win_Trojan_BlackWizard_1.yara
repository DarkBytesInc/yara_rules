rule Win_Trojan_BlackWizard_1
{
strings:
	$a0 = { 89078cd80e1fbe910881ee030103f38904be930881ee030103f38cc089040e0753b8002fcd218bcb5bbe330c81ee030103f3890c83c6028cc089040e07bfb7 }

condition:
	$a0
}

        
