rule Win_Trojan_Mybot_8443
{
strings:
	$a0 = { 1a77ac4e2d038e2204483bcba5ce9feafa83d342407dbb59e616b74bc7a3f93acfcf729096ce08789516c339226997cc2e3724398e72370dae25f7467d391aa135be30911dcdbe47a8840ca0fb8d72c060cd0bb374 }

condition:
	$a0
}

        
