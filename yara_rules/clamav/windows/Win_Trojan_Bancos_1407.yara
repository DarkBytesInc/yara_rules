rule Win_Trojan_Bancos_1407
{
strings:
	$a0 = { 77b7b8bf09ec5aa3ed0f2551cb20a127577e7e6cad05850620b5088683d9394e85edb47aaebb5b3ec9c4551ce9f08ad415cb9b17d7d04ce5db77230fe12f393a2ed413057ac1f1634d667b90e475e51cdc4eb603158621b45f950ab3 }

condition:
	$a0
}

        