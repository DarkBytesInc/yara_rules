rule Win_Spyware_Banker_3445
{
strings:
	$a0 = { 98250e09f41e27fafec946a83bfa1322e4f40ffb54b18d75c1255d9eba772ec457e8833a0ba510cd17ae0afc32398eb1e51cdfe8f6f04006c8cc752cfa2a5a1328b8ebc2d4772e0a8d04b71a2244d50c4ef94ee1ef2848b403de86286b4662 }

condition:
	$a0
}

        
