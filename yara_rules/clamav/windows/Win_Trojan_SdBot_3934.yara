rule Win_Trojan_SdBot_3934
{
strings:
	$a0 = { a1665a2f7d642ccb8db6782581e2592eec05555ee7ec845dc9608a112baadc9f58e67045921bddef0d3cebd60d53b38705eb50dcb36b5cbb6949e29fb612a914c3bc28f02dd7d9f4d18b0f62e0dddc857658fcf6dc83ba33bf8330ef }

condition:
	$a0
}

        
