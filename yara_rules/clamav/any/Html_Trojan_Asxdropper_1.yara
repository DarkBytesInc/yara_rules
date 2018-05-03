rule Html_Trojan_Asxdropper_1
{
strings:
	$a0 = { 3c4153582076657273696f6e3d22332e30223e }
	$a1 = { 3c4d4f5245494e464f20485245463d22 }
	$a2 = { 2e65786522 }

condition:
	$a0 and $a1 and $a2
}

        
