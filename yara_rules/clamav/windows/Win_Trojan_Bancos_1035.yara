rule Win_Trojan_Bancos_1035
{
strings:
	$a0 = { 4a3a7db4180b0983cf9b1187755f31ae2455cd4417eb21f902937df3fa7ca13d999010a92ed509786d55c71d87ce5e6acde1775567e81b1d74f9e4892dbab85beb374fc8a21d7cd32fff894f46ccf19657f6 }

condition:
	$a0
}

        
