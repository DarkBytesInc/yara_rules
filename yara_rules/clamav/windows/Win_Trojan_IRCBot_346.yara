rule Win_Trojan_IRCBot_346
{
strings:
	$a0 = { 5c1404d73cf0fab01f4521071da0bc39b8641b41576748993e65cc6ebbfdb2c870ba8176d897c0f2e0069fc0d612b8d96e2a02f63e4d43b07415ab903682eb2fff05fb9fd88c222855608f4fc0e0d6ec }

condition:
	$a0
}

        
