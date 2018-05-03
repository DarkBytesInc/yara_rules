rule Html_Phishing_Pay_271
{
strings:
	$a0 = { 332e3232302e352e3133372f7e6c6f61646d616e2f }

condition:
	$a0
}

        
