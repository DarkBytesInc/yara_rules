rule Email_Trojan_Trojan_840
{
strings:
	$a0 = { 6e6f7720726561647920746f2076696577[0-10]526566657220746f[0-16]66696c6520746f2076696577206d6f72652064657461696c73 }

condition:
	$a0
}

        