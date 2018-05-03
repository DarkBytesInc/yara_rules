rule Html_Phishing_Auction_86
{
strings:
	$a0 = { 3c6120687265663d22687474703a2f2f32 }
	$a1 = { 2f656261792f6c6f67696e2f223e68747470733a2f2f656261792e636f6d2f6177636769 }

condition:
	$a0 and $a1
}

        
