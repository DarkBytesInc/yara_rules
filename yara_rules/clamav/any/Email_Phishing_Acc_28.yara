rule Email_Phishing_Acc_28
{
strings:
	$a0 = { 5375626a6563743a2055504441544520594f555220454d41494c204e4f57 }

condition:
	$a0
}

        
