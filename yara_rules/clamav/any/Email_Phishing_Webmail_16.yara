rule Email_Phishing_Webmail_16
{
strings:
	$a0 = { 436f6e66697261[0-15]612063656e6120646520426574266174696c64653b6f2065204672616e }

condition:
	$a0
}

        
