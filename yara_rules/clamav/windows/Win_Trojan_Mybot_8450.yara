rule Win_Trojan_Mybot_8450
{
strings:
	$a0 = { ff5beca9e3c864279ad48551d8a1bad5542d48c174158a0a2c041e38d949cf84842f51b65d4cad24d83f01c3c1e31056bc12140abfacdfa48187cb03f020f983f1ffa4b57ecf61c6720481e148b675291c25bd94d3 }

condition:
	$a0
}

        
