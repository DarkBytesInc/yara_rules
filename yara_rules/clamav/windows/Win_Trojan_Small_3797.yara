rule Win_Trojan_Small_3797
{
strings:
	$a0 = { 18acffadc956178a8c639acddc41dd3a884229928d825b2be0a66cef3c57170721b0810820b67564231a6c92b4a8685a1eaea284d0d97c0fc8e15e43cb1d26be105d9cd051a4138607e4c70fc956 }

condition:
	$a0
}

        
