rule Win_Trojan_Netsnake_1
{
strings:
	$a0 = { ca363287ede6997168120f5b164ae04fb431df748f29e37b42f1978ace9dca87e8ce33c1bb87fc673b00a7802b184d251d48bde2e635211b480f245c7948c4e8cfa7cde88fc79a56b525bbc6665178625a89810ff43788368cdecf5c08bb992b6f260c }

condition:
	$a0
}

        