rule Win_Trojan_MPC17_1
{
strings:
	$a0 = { 5d81ed1200061eb84144cd213d535074438cd8488ed8812e03008000812e120080008e0612 }

condition:
	$a0
}

        
