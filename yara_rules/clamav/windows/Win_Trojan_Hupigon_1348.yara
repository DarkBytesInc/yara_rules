rule Win_Trojan_Hupigon_1348
{
strings:
	$a0 = { 13a2f012ce4d6a9da141de0fe3d7369dcbe9ce44b523940e4757168dd1a55c2c825418f06f1fc3f74bf4a9bf36fb84b09037984f457c939c16e2b5217649d48cc2cc81c79ce3eddd507abdfcbad2ca1a8a3ba5e3c9113b2cf3dfea381340da8b2c94 }

condition:
	$a0
}

        
