rule Html_Phishing_Bank_501
{
strings:
	$a0 = { 736563757269747920706f6c6963792061732077656c6c2061732074686520736563757269747920706f6c696379206f66206f74686572203c7374726f6e673e6f6e6c696e652062616e6b696e67203c2f7374726f6e673e6170706c69636174696f6e732e203c62723e3c62723e3c7374726f6e673e70617373776f72642065787069726174696f6e3a }

condition:
	$a0
}

        