rule Win_Trojan_Hupigon_1359
{
strings:
	$a0 = { 962d1ae2f1911187f9f2d0e63c4c806a87e6d68b07179cb90fdadb1a824e45d633b5052dd2c1cbd500deba9573bc6b6aa79f741ea19388091cc8ed0be6aefc67331c559eaa7ca41f84e75f209ae916fb4b12b19e0e84ca2c6655e0b016f0bbc9282f }

condition:
	$a0
}

        
