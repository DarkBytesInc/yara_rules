rule Win_Trojan_Spambot_248
{
strings:
	$a0 = { 23a8b07c4331c73c10ebd21cc1d92a70061169c1ffffffad75805ddc4737bf7e5f5c4926ca74803e853251369639ea716297ffffaffffc4c249f43e287bded70c912a6d6b67ab2eccef7ec79ea1ee71ffeffff773bbe7523ac8c6255ad9c2820213be159447fe77619a05da2d2ff }

condition:
	$a0
}

        
