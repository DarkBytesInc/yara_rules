rule Win_Trojan_Bancos_1308
{
strings:
	$a0 = { 70131bbbfde41ad40f3af3f8583ea286a7ae63b066cfaae53559b2b2af7bfa11fb80c89de3b199bc0b7996192a6e47ec13c671aa5fe88015201f90fbf4d6ef2d5363e01c201b8837faec88aa95323fbc3b028962f7bbcc68bea2 }

condition:
	$a0
}

        
