rule Js_Trojan_Obfus_231
{
strings:
	$a0 = { 666f722876617220703d303b703c7a3b702b2b297b766172206d653d66616c73653b707a3d66616c73653b766172206a683d66756e6374696f6e28297b72657475726e20276a68277d3b636d3d33313436393b793d7061727365696e7428286d615b7a2b705d2d647177656e2e7177746f73292a6e2a302e32292b7061727365696e7428286d615b705d2d647177656e2e7177746f73292a6e2a302e32293b66756e6374696f6e206528297b7d }

condition:
	$a0
}

        