rule Win_Trojan_Banbra_115
{
strings:
	$a0 = { bae3af5bdd1456c78a619e310d19441f0766196c2f371cca5e0ca1c74be99f3ce9dc30251ef95c832abb0e9776be2db9a36d248baf082e96bb4d25f27dfa48e662a7ba1f5fe0fa0f213ffe963fc83e0d95be5aff6164ee691be22f61b8d24a010dddf582a84b367d09033b4d4857 }

condition:
	$a0
}

        
