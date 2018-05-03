rule Html_Phishing_Bank_1341
{
strings:
	$a0 = { 70616372726f73746f72652f636174616c6f672f6e6174696f6e776964652e636f }

condition:
	$a0
}

        
