rule Win_Trojan_Mybot_4316
{
strings:
	$a0 = { 7bd09f6b46dad0fc6b46b9d0d952d07b79436348dada93da489d0d5bda5ab05b3db53bf43b743452bc29bd8e451dab9f6fd05c4d7cd15cbca632dc9fdaa89db557e7cbdf3e3e5a1d311343cb0a3b4acabac59dc8d33fd6647bc08ab28103aa113b5fca9fe859f4a9b43b4c093f4c9e1b437823f0bb7e42a9cf6aba33485f535b7f8a01616e7f4a019a618e93938a93e7ca43b045f374 }

condition:
	$a0
}

        