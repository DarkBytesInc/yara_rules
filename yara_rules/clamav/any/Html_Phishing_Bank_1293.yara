rule Html_Phishing_Bank_1293
{
strings:
	$a0 = { 7669736974206e6f77206f6e6c696e652062616e6b696e67207061676520616e64207369676e206f6e20746f20796f7572206163636f756e7420666f7220766572696669636174696f6e2070726f636573733a203c6120687265663d22687474703a }

condition:
	$a0
}

        