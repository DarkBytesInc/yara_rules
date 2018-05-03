rule Email_Phishing_Bank_913
{
strings:
	$a0 = { 7565726f32342f6b656e2f63686173652f7570646174652e68746d223e }

condition:
	$a0
}

        
