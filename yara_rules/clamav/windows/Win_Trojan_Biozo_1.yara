rule Win_Trojan_Biozo_1
{
strings:
	$a0 = { 610062006c00650064002e002e002e00000022000000490063006d0070002000410074007400610063006b0069006e0067002e002e002e0000002b3dfbfcfaa06810a73808002b3371b56711d4a80cc3ce4eb995e4d97a6a971a2a3dfbfcfaa06810a73808002b3371b56327c0823d38b5 }

condition:
	$a0
}

        