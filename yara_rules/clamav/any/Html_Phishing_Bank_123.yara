rule Html_Phishing_Bank_123
{
strings:
	$a0 = { 656e73757265207468617420796f7572206163636f756e74206973206e6f7420636f6d70726f6d697365642c2073696d706c792066616c6c6f772074686520766572696669636174696f6e2070726f63657373 }

condition:
	$a0
}

        