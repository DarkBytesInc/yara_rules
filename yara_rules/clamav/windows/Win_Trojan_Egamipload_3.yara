rule Win_Trojan_Egamipload_3
{
strings:
	$a0 = { 57696e446267457874656e73696f6e446c6c496e6974[4]73726366696c6573[2]44424748454c502e646c6c }

condition:
	$a0
}

        
