rule Win_Trojan_Alex_9
{
strings:
	$a0 = { 616c65782e64656c65746566696c65202822633a5c6175746f657865632e6261742229 }

condition:
	$a0
}

        
