rule Win_Trojan_Bancos_722
{
strings:
	$a0 = { 38d62bc81830eb39fee0b8ae0e87c3ab5243539d3cee9eda664e63f35308ed9408a8b8155801c2b6dce5f3b708ef090bd7118d7285d10dc883775566c2d4e42d6b39cc126b674a7693075d2179dcd1b3 }

condition:
	$a0
}

        
