rule Win_Trojan_Batalia_1
{
strings:
	$a0 = { 6620222531223d3d22322220676f746f20730d0a666f722025256220696e20282a2e6261742920646f2063616c6c2025302032202525620d0a676f746f20620d0a3a730d0a6966 }

condition:
	$a0
}

        