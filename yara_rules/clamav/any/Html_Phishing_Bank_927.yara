rule Html_Phishing_Bank_927
{
strings:
	$a0 = { 2f2532302f7777772e654261792e636f6d2f696e6465 }

condition:
	$a0
}

        
