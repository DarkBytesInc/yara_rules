rule Win_Trojan_Bancos_1946
{
strings:
	$a0 = { d3dffdf1febe92d59fda9e6f46cc3ac19f82abe3bac14bd8f2c93493d31b9ae158ec40eaa8796a89e6a56b466f3557ebd7840b5f875384a92bb1462931548abe87d66630d51ddae884b39da75546bbc61313517723351248230a }

condition:
	$a0
}

        
