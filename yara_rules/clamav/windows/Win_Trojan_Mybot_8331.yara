rule Win_Trojan_Mybot_8331
{
strings:
	$a0 = { bc76752ed8d449f6f9b6f7560ce854903e091b9857ad1e0cacbee89cef8f27a6b1611ea67e317dac808ea6b6bc414d2b155e2ced637a6462d5ba5e80c426773c7bb29e154546dd5b3443e926f43366c0 }

condition:
	$a0
}

        
