rule Win_Trojan_Mybot_8488
{
strings:
	$a0 = { f375c7a9fd1b728616aceef2db53384752e12b0d1ab5313a08eb2a2a57a529d48e8e82905c5214abfe91f551a3a6b4d41a5a71d951dc100755b4342d2dc5f62bd145e6b285a7bb27eb3c2a30a587f459b4b4ba9831 }

condition:
	$a0
}

        
