rule Win_Spyware_Banker_2216
{
strings:
	$a0 = { 9ad5978e810ab135dc148393d6cb086535b53ffc05c21a53d4269f13cf364408cc6e9980e8fdff2f9bc473ba5802c7c45130e88da0a5bcccef53c3e9f5464de1af0ee6382fffadca98bd3f61d89b09546f73cb32b72c9390ce455adaefb683082dd180da }

condition:
	$a0
}

        
