rule Win_Spyware_Banker_4045
{
strings:
	$a0 = { 136d77bc96d1b4b52ef73751b4b484d7de9a9a3dd68e93a2d45a6f7b40bcce659acce73372357324b6f377505ab23da4829241119a8c0901784cd02b3205699a1e9320f5c9104cd41530808628d4c2021855470440ca2d5cad5ae5def7ce5ce39ccce7fffffa7cf7f79fbce9ef9ef7fbed7df7d9903f79fde7ef3fbcfec9852db779f754a6db870abcda38ea }

condition:
	$a0
}

        