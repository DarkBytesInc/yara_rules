rule Win_Trojan_Aimbot_20
{
strings:
	$a0 = { 7934673bd949a5f32865a07c1bd11cff60fb38011021e81c51d69cfaee4c9b72107c14d9f7240eec6c1ad92152b3326f62635c226b7084cc25c062cf71f19388fb4926756128aba0ad0c2a5fa6b84611e810e7e8a20d1756e96356f833a5b9d0103e8bce26aedd77191ee4de8c0a5923a1b786669c0b2325954659 }

condition:
	$a0
}

        