rule Win_Trojan_Giri_2
{
strings:
	$a0 = { 57696e33322e47697269676174206973206e6f772061637469766521 }

condition:
	$a0
}

        
