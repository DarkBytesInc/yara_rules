rule Win_Trojan_Crypt_201
{
strings:
	$a0 = { 33c07404c707a08f56532bde5b535233d35a50891c242b342483c40452331c245a52528b5c240883 }

condition:
	$a0
}

        
