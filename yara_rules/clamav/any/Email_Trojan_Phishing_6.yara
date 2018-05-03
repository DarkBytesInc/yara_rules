rule Email_Trojan_Phishing_6
{
strings:
	$a0 = { 676472626868737764636c2e6b69727970726f2e61742f75706461 }

condition:
	$a0
}

        
