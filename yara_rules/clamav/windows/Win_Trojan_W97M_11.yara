rule Win_Trojan_W97M_11
{
strings:
	$a0 = { 5072696e742023312c20564250726f6a6563742e5642436f6d706f6e656e74732831292e436f64654d6f64756c652e4c696e657328312c203029 }
	$a1 = { 496620[0-20]2e4c696e657328312c203129203c3e20222722205468656e[0-20]2e44656c6574654c696e657320312c20[0-20]2e436f756e744f664c696e65733a20[0-20]2e41646446726f6d46696c6520 }

condition:
	$a0 and $a1
}

        