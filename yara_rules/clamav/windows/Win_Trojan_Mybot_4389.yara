rule Win_Trojan_Mybot_4389
{
strings:
	$a0 = { 6948630032247361bd7ff46e007a647b771e204e5430c7438e1765ed018cd3bff9c2395dc88029005b38d435a9423409f320bf64487541730049e13e8e304cf34e018af23dafc28583d4f9f8fae63a2610790e8b15e42240bb629a0eaffbf03a030701a73660aac04d428c25012bab318a924410ccb650016ee071da2e59fe2a803d820b4700bdc6c35f124ad7ec7e1f3dcfbe9f3043 }

condition:
	$a0
}

        