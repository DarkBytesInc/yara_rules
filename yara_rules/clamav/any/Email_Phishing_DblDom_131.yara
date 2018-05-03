rule Email_Phishing_DblDom_131
{
strings:
	$a0 = { 687474703a2f2f[10-30]2f6f6e6c696e652e6c6c6f7964737473622e636f2e756b2f }

condition:
	$a0
}

        
