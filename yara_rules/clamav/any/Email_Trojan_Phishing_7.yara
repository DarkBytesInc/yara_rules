rule Email_Trojan_Phishing_7
{
strings:
	$a0 = { 446561722057555220456d61696c20557365723a }
	$a1 = { 77697468696e20343820686f75727320666f72 }

condition:
	$a0 and $a1
}

        
