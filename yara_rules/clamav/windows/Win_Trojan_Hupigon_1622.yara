rule Win_Trojan_Hupigon_1622
{
strings:
	$a0 = { 702cb458820a0f45cddb124ccf5ac3385e9361f97d6ac8b11286a429a5749a4de1876d11ed456dfc465155b540da5ee5d8955c00acf46befa8fdbe48ff1d7c723b645a8a773ce4c4f9042e112c306cb6bc9dfe9faba90815fb20 }

condition:
	$a0
}

        
