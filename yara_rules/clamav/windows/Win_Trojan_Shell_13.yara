rule Win_Trojan_Shell_13
{
strings:
	$a0 = { 6563686f20246f75743d282273797374656d223d3d2473656c65746566756e63293f73797374656d28247368656c6c636d64293a28282473656c65746566756e633d3d226578656322293f6578656328247368656c6c636d64293a28282473656c65746566756e633d3d227368656c6c5f6578656322293f7368656c6c5f6578656328247368656c6c636d64293a28282473656c65746566756e633d3d22706173737468727522293f706173737468727528247368656c6c636d64293a73797374656d28247368656c6c636d642929 }

condition:
	$a0
}

        