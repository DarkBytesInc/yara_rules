rule Html_Phishing_Bank_923
{
strings:
	$a0 = { 616a616d61647269642e686b2f706172746963 }

condition:
	$a0
}

        
