rule Win_Trojan_Bifrose_90
{
strings:
	$a0 = { a715af4279a4879af4676b55e87d4f10eeaecc080345e8e48ee713d8b84b5a9789429ad6d542cd38e43e1ff4d467b1c2d9e8f3d42f9533b4456be2af1d4a3d61c103e46a570fd1b8ef7ac187211cdf057a1617bcd6bcda0b7ef03e96f7c47111de6e121662b5ccfc4ed0a1793b16faf0dca6e876c1737cc6cac1763a67e8519df83eec515cb191ddecaf665a }

condition:
	$a0
}

        