rule Win_Trojan_LookOut_1
{
strings:
	$a0 = { 9a07696a963340303f38ae9b6f09fcff10888395f640a44c185a9545b830f500f9b6bbff473c4c6f6f6b4f75740bdedbdb4fff1d88ffffc10602035d9efe039aea024d998c751563fdf92ea103d67c3d98a8490120177b6bf00b58466c619f58746f6e0f }

condition:
	$a0
}

        