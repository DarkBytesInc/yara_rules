rule Win_Trojan_Bancos_969
{
strings:
	$a0 = { 571bf5a7724f3a44ee831d8199e8a79c108a3ce890d3290a8c8ce65701765aed6a2973d1b19f39d17849c1dfcb0db601d1011357bc6e651f599f52f0abf8e0e2cd6fcf8ac5034ba5fdc45e2a70623605d306 }

condition:
	$a0
}

        
