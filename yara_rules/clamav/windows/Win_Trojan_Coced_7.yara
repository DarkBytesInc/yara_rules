rule Win_Trojan_Coced_7
{
strings:
	$a0 = { 77732773683d27000000656c6c6f00000000e5e9e1e4a8eefae7e5b2a8f2f1f0c8eaededfaa6ebe7e500f4f8f0f5b7faf6f4e9eceafcebeffcb7faf6f40048cdc4c7a8c4c9c5cddad22400000000b1a5a3b2a7b7a9e9e6e4a2b5a3a3f5b0adaa86e4b1a9a0b5f0aaa8b7b5a9ada3 }

condition:
	$a0
}

        
