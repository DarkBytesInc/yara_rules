rule Win_Trojan_Coced_11
{
strings:
	$a0 = { e7b3e7fca9b3fff6fdfafda2aaa2a4d3e6e0f2bdfdf6e72400e5e9e1e4a8eefae7e5b2a8eae7eac8e5fbe6a6ebe7e524004365727a7573642a30000000756477732773683d2700000048cdc4c7a8c4c9c5cddad22400000000f4f8f0f5b7faf6f4e9eceafcebeffcb7faf6f400 }

condition:
	$a0
}

        
