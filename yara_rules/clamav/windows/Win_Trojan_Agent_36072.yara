rule Win_Trojan_Agent_36072
{
strings:
	$a0 = { fdffff31d029c989559c0995e4fdffff29d1298d34fdffff4183f900761f4931d129d1baef000000119514ffffffff4d9831ca81eaf700000001d131d14a4ac9c3cccccccccc558bec81ecc802000029c9218594fdffffb8580a0000ff8524feffffff85 }

condition:
	$a0
}

        
