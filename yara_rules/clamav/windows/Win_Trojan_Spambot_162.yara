rule Win_Trojan_Spambot_162
{
strings:
	$a0 = { ff53b544d11b60d34310af9d404593ffffffff9b15307ca17140b30f45f62ddc9b3ec3324635725f5b8daea922522e8586ce28ffffffffc7108211afd865bc355010ea898d4de1bada668a50cd20ae603f7b21371b70dcfcffffffa1957ec35136c15bbb76d96972efee5a729ada }

condition:
	$a0
}

        
