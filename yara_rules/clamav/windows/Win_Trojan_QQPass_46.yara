rule Win_Trojan_QQPass_46
{
strings:
	$a0 = { dacfdf03d7b4ccaca3baf261416574d0726797c1086220696e6b6b1c74e91f66255b551d7749612e0e7c63636f6de72073677264003f563d312655696eed5c88438826530a6974653d264f8f4d476e75c779f0733e3c69fa671b20626f66e7313d2230cbd8535243a5556c143ffb97a43ab21c9e9735b20452c4d0e4ae4688290b2c804950b5d8d6b7a450530d1405ceefc0ed2516 }

condition:
	$a0
}

        