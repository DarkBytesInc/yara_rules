rule Html_Phishing_Postcard_4
{
strings:
	$a0 = { 36342e31392f7e656c2f706f73742e657865 }
	$a1 = { 6f737463617264732e6f72672f3f }

condition:
	$a0 and $a1
}

        
