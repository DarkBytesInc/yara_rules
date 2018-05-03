rule Email_Phishing_Webmail_1
{
strings:
	$a0 = { 596f752077696c6c2062652073656e742061 }
	$a1 = { 736576656e0a64617973206f6620726563656976696e67 }

condition:
	$a0 and $a1
}

        
