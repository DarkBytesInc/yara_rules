rule Win_Spyware_393_2
{
strings:
	$a0 = { fc56300cea4079c4da413345f5786aa64ef0130adcc15047bd56dee2b1f880b9f103fd282165f17615d8fdebb55cbfd3cb1bd23bdd2d39b7f328f8cdee3b92f1e8a62d85ec5b9edcfff3fbcd53d84dd3c4d4a86811c7edb8f760b8dbd5702df36f737001 }

condition:
	$a0
}

        
