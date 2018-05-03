rule Html_Trojan_VBdo_1
{
strings:
	$a0 = { 03000000140000003171cb83a0be1e260b724d061aff28c1ff91fcff86ec7a3fffffffff00000000433a5c4d792053686172656420466f6c646572 }

condition:
	$a0
}

        
