rule Win_Trojan_W_274
{
strings:
	$a0 = { 5e8d7c2420a5807f082475698b5f18ad9733c0870760ad97578bee8b732ca44fa675fb5e33c0b4d599428d5a01ffd5724233dbb7d6939933c9b50360ffd53b }

condition:
	$a0
}

        
