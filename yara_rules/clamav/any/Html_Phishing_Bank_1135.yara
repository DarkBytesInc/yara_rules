rule Html_Phishing_Bank_1135
{
strings:
	$a0 = { 796f75206172652072657175657374656420746f20666f6c6c6f77207468652070726f766964656420737465707320616e6420636f6e6669726d20796f7572206f6e6c696e652062616e6b696e672064657461696c7320666f722074686520736166657479206f6620796f7572206163636f756e74732e[0-20]3c6120687265663d22687474703a2f }

condition:
	$a0
}

        