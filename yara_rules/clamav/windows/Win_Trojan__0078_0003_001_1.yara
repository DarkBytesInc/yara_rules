rule Win_Trojan__0078_0003_001_1
{
strings:
	$a0 = { 01b91900cd21b4408d962203b9f801cd21b4408d961403b90e00cd2159888e110380ae1103 }

condition:
	$a0
}

        
