rule Win_Downloader_Banload_982
{
strings:
	$a0 = { e2586b827beb9c941abaa6789d105ab42fec24b8d7b869956b0b7ce6bd10af60cfa88b4b664db64af6bdd4a5d6cdf785d77b52b51d2bbbcc690c19f86e760c5a483bb70e3b0fb9b58657aee43bff60b7ba835cb99e7762a849e203b8baaba51614112db321416ebdf92112b10597 }

condition:
	$a0
}

        
