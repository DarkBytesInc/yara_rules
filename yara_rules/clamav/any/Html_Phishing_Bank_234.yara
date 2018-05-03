rule Html_Phishing_Bank_234
{
strings:
	$a0 = { 74703a2f2f7777772e6761632e6c742f6765656b2f7777772e7563752e6f72672f6e657768622f68 }

condition:
	$a0
}

        
