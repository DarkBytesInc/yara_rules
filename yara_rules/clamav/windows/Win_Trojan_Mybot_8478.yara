rule Win_Trojan_Mybot_8478
{
strings:
	$a0 = { fcf8c4df87bc3f7b86c86040f22dded5be6867115241e5e7534ee467a6e5d23d05fce1eaaf8556bd0d2f568daf4562e145d65ec51ab1de5645b3fd6ad9272ba397f8da327a751f0ef46c4776bf9b4a6d0b2dc3148a }

condition:
	$a0
}

        
