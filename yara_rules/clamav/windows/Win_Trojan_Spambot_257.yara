rule Win_Trojan_Spambot_257
{
strings:
	$a0 = { 12816835fa067586d8daff1fe0ff49c631b13daae44882f6133f986c91ff9880a78757a5ecffc1ffff7f701b3ce8671b8dda7fd634de2866619b8df7d00cf4bd2aad1efffffffffbeb9c93cc3a4a625f3cc9692927516df9026cd44e5c61da4bcf124fe44eb710fffffffffee9c6 }

condition:
	$a0
}

        
