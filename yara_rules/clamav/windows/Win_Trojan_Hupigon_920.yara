rule Win_Trojan_Hupigon_920
{
strings:
	$a0 = { e025e17bb75bdc6dc463dd4d7b102a7b3e5926ff4d4f1716493dc52f8b42f8e217c6fcbe2d4be37c5f1c12f8de8d9d65ebad06239eee3848b9fb37dc6358d81c6159f9bd75c6c284ecd9abaff50d9bf44d84f4045a83edd3fb07db67f6143b7b0816 }

condition:
	$a0
}

        
