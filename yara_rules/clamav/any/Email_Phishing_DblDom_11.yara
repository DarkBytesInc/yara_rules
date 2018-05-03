rule Email_Phishing_DblDom_11
{
strings:
	$a0 = { 687474703a2f2f7777772e6f6e6c696e652e77656c6c73666172676f2e75736572 }

condition:
	$a0
}

        
