rule Win_Trojan_Small_3572
{
strings:
	$a0 = { 57f3a13433916f6c8a1f15e108638894d1191e95907d12ec2d9a3b6939730625d614d8042e665527771645e8d7105e1c0775d02e8af7fa4568a34ff54705652f79d410229f1ff513ea8151243594 }

condition:
	$a0
}

        