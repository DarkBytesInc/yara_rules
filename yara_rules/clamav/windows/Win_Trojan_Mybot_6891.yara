rule Win_Trojan_Mybot_6891
{
strings:
	$a0 = { a4b9fa157a36ae3c1f7a1d32b85dc138565e89166dc1e96c4f032d89e604f89e4d59d1911f257448d3582e177c20ae90372ce204c6d6494756f61a0ff240459edc81f96d566333f2070a4b806ab35dca74538c75e6a39894f078739af0049d5e38e2d56ed1491c4cfce68ed572da19f10958df574afa083c2da7d52a973c22e31da1769c50d67cd2292a0c5320fbd502a70a7122641e }

condition:
	$a0
}

        