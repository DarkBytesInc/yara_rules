rule Win_Dropper_Dorifel_3
{
strings:
	$a0 = { cccccccccccccccccccc790600a030274a0078214a00000005000000002b02ef011201001a01004200ff03240000000109005374696e6b68 }

condition:
	$a0
}

        
