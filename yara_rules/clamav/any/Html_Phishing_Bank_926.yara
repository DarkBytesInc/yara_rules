rule Html_Phishing_Bank_926
{
strings:
	$a0 = { 703a2f2f652d676f6c642d736572766963652e636f6d2f223e3c623e63 }

condition:
	$a0
}

        
