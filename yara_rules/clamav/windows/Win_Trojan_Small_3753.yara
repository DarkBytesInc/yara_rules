rule Win_Trojan_Small_3753
{
strings:
	$a0 = { 85f18e9217b2a60cc1f03ea495c47e3c0299c63fadb0c100c6063d14ee0094a6ae03a624c1f03e919522413cad330255ac256254acc6464cedb09d9a0a0c97ff0308a63cbdb03ea6b5af5374bdf03e8cacc67a4cedb0c92c18b1a85f031b3e3bc3044e7cad35feb0df3b7b6cbdf03e92ac88c3 }

condition:
	$a0
}

        
