rule Win_Trojan_Fakescan_1
{
strings:
	$a0 = { 28297b77696e646f772e6c6f636174696f6e3d22687474703a2f2f69776167696c792e636e2f696e7374616c }

condition:
	$a0
}

        
