rule Doc_Trojan_Razd_1
{
strings:
	$a0 = { 496620576f72642e54656d706c617465732831292e564250726f6a6563742e5642436f6d706f6e656e74732831292e436f64654d6f64756c652e4c696e657328????????????2c2032202d203129203c3e20222752617a6465676f22205468656e }

condition:
	$a0
}

        