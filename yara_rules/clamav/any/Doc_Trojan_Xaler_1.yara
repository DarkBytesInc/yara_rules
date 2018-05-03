rule Doc_Trojan_Xaler_1
{
strings:
	$a0 = { 6b6b26203d20496e53747228312c206b65696d656e6f2c20222752454c41582229 }

condition:
	$a0
}

        
