rule Win_Trojan_N_67
{
strings:
	$a0 = { 6e33322e536f6e696100432076657273696f6e2077697468207370656369616c206c696200532f617368205b5274435d0057696e33322e536f6e696100486176652069206675636b65642075702057696e33322e536f6e6961203f002a2e6578650000 }

condition:
	$a0
}

        