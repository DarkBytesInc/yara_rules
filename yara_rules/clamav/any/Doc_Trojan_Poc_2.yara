rule Doc_Trojan_Poc_2
{
strings:
	$a0 = { 706c69636174696f6e2e4f7267616e697a6572436f70792056536f757263652c20565461726765742c2022634c45414e4572222c2077644f7267616e697a65724f626a65637450726f6a6563744974656d73 }

condition:
	$a0
}

        