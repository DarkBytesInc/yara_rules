rule Email_Trojan_Trojan_762
{
strings:
	$a0 = { 417474616368656420746f20746865206c6574746572206d61696c696e67206c6162656c20636f6e7461696e73207468652064657461696c73206f6620746865207061636b6167652064656c69766572792e0d0a596f75206861766520746f207072696e74206d61696c696e67206c6162656c2c20616e6420636f6d6520696e }

condition:
	$a0
}

        