rule Win_Trojan_Mybot_7517
{
strings:
	$a0 = { a94eb33de2898b9c291ff7dea989fbd8e100d3ba295acf26aab4c3e6e10f9b412985c707a8ff8b6ae1b2e34f29c09f4fa93ad388e075abea280bd72ca9659b56e024f3302836af8857afe39defe3bb7f2871a765a8ebabbbefbe8302d7bcff5aa816f346ff91cb20d7e7b7b25650bb4cff5893afd6228f98569b83e8fe07dbf5 }

condition:
	$a0
}

        
