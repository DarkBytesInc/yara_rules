rule Win_Trojan_Agent_33369
{
strings:
	$a0 = { 2f32c333bfcebacf8ef5599e5df8050b2ce64388cad51ee0a1986fd3440b5260c65a25f27a79800f06e848ee09cb9da8bfb8e362f979e1e58b5fb8897d88d1f0e8da0a23d65fbefe2e7ca61c294ba526e1cc6a8aad43ccd7a8bd91d7 }

condition:
	$a0
}

        
