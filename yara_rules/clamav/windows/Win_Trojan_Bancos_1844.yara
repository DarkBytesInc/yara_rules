rule Win_Trojan_Bancos_1844
{
strings:
	$a0 = { 604144fb35febd7497f879206a427f800b31123b98b5012e03d8d3123bc8eb3bfb4ad9b6bb9ea395d30d93849c5da7e128b569a7e65830296ec6f341c57aa8d406ccc66fe727 }

condition:
	$a0
}

        
