rule Win_Spyware_ot_265
{
strings:
	$a0 = { 0455b85692a467e72ca451d436e10f710223d17094834939fff7ce194dce185315e7fcdd11f2bd29ccae021c98ebcd54f2698e21d0d2ff1c0cf88e9af7740bc6bcf3d1481967ec5ba98bb099a0b7ea58174ff7c3599ac0f9 }

condition:
	$a0
}

        
