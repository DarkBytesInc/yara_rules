rule Doc_Trojan_Thus_8
{
strings:
	$a0 = { 66204170706c69636174696f6e2e446f63756d656e74732e4974656d286b292e564250726f6a6563742e5642436f6d706f6e656e74732e4974656d2831292e436f64654d6f64756c652e4c696e657328322c203129203c3e202227546875735f30303127 }

condition:
	$a0
}

        