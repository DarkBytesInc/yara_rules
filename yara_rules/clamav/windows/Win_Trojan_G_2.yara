rule Win_Trojan_G_2
{
strings:
	$a0 = { 5d81ed1300061eb84144cd213d535074428cd8488ed8812e03008000812e120080008e0612 }

condition:
	$a0
}

        
