rule Html_Phishing_Bank_12
{
strings:
	$a0 = { 62696c6c2070617920666f7220616c6c206f757220636c69656e74732e3c2f703e3c703e617320616e206164646974696f6e616c207365637572697479206d6561737572652c20796f75206e65656420746f2061637469766174652074686973206e65772066656174757265206279203c6120687265663d22687474703a2f2f }

condition:
	$a0
}

        