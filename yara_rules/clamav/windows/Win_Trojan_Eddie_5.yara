rule Win_Trojan_Eddie_5
{
strings:
	$a0 = { 4d5a88414c4558303330323c[0-147]5c434f4d4d414e442e434f4d[0-1]2121427162216566716a747562756221 }

condition:
	$a0
}

        
