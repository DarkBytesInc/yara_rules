rule Win_Trojan_Bifrose_424
{
strings:
	$a0 = { 5533e533e55de9a815000000bb736914e1e87f7fcf0a1f37b94845f6b7dcab33e3dc4b00de952f1d8d00d5ecc5d6f968ffcbb7885d2ca1da9b30c51cf2bbd4e60fe97046a3a7fc56a72455b25e2899ce8794cdf26368fd6667147d76eb5889f0f2a4cc8b }

condition:
	$a0
}

        
