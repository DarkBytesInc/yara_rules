rule Win_Trojan_PSW_23
{
strings:
	$a0 = { 65726e656c33322e646c6c000000007175697400000000756477732773683d27000000656c6c6f00000000bfaebabaa8b9a2f0eeecb8bfaea1e58da4a4afe5a8e3a9a1e5000000e5e9e1e4a8eefae7e5b2a8f2f1f0c8e5fbe6a6ebe7e50000f4f8f0f5b7faf6f4e9eceafcebeffcb7 }

condition:
	$a0
}

        
