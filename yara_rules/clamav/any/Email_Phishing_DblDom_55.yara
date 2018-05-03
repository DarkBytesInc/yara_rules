rule Email_Phishing_DblDom_55
{
strings:
	$a0 = { 687474703a2f2f6f6e6c696e652e766f6461666f6e652e636f2e756b2e }

condition:
	$a0
}

        
