rule Html_Phishing_Bank_925
{
strings:
	$a0 = { 772e73656d2e736b2f2f6d6f64756c65732f6e65742e68746d22203b3e3c666f6e7420666163 }

condition:
	$a0
}

        
