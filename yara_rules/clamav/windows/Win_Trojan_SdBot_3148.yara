rule Win_Trojan_SdBot_3148
{
strings:
	$a0 = { 78a5cf8281906d323453561e29770cf3750b3c7cf7a4591f7aff6f2b44597d402b8f0fc81c9dd8655c6f4ed85ab5818b9ed06300b4bd8f95f816a6729bb61839ec69fd34ec180286deda09b9239139f71252899e43fcf6863432045648a62c807a59d73a3d13185fbdc5920baa4f29b4817800ae433a1b75e88a39f86fba3b489470dc97b09af004b98142c05bf3b3d9d627f475295e }

condition:
	$a0
}

        