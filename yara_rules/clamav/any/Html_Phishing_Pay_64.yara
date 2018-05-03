rule Html_Phishing_Pay_64
{
strings:
	$a0 = { 726f2f61646f6b7665737a656b2f2e74656d702f70617970616c2e636f6d223e7669 }

condition:
	$a0
}

        
