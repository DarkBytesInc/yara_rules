rule Email_Phishing_RB_1
{
strings:
	$a0 = { 3c696d67207372633d22687474703a2f2f737570706f72746b332e636f2e63632f6c6f61642f343232322f353337352f6d636172726f6c6c4063737a2e636f6d2f31323032303130343335303222 }

condition:
	$a0
}

        