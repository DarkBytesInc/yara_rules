rule Win_Trojan_Hupigon_140
{
strings:
	$a0 = { aee9aa5f0b7346110667c712eee817733a015bd2ed456953ff834fe7753ceb68fc37c045d6635119f7db27019524001032eee13f5538b243290f972cf4a7e1464adbafafcdfcf8e48022d0ac64b8f5257381afe45fbb7a1dc5ea }

condition:
	$a0
}

        
