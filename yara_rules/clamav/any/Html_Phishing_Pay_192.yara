rule Html_Phishing_Pay_192
{
strings:
	$a0 = { 636f6d6520746f206f757220617474656e74696f6e207468617420796f75722070617970616c2062696c6c696e6720696e666f726d6174696f6e20617265206f7574206f6620646174652e2074686973207265717569726520796f7520746f2075706461746520796f75722062696c6c696e6720696e666f72 }

condition:
	$a0
}

        