rule Win_Downloader_1008_1
{
strings:
	$a0 = { 63d18a7e547beb1881baa18df647024ac428625b91a68b4531a057f8554d8e1c487808bf8441abb55fb10136b50c84b76d4333c8ae321dbb6f6c1222e0f41bfbbbf9dc6e31b0b6fcbc2650ceb62c9fe773e8fee8fec0e68ac0c41e0c }

condition:
	$a0
}

        
