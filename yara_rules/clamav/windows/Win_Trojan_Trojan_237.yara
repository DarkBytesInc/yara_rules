rule Win_Trojan_Trojan_237
{
strings:
	$a0 = { 812f23394343e2f70b3a2396a4263539413fdb7a670644767689978fd783de38220744bc0e89d783f05a957fa6672539 }

condition:
	$a0
}

        
