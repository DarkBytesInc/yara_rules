rule Win_Worm_Stration_559
{
strings:
	$a0 = { 6e766f216473736e730100003600000020000000630000004d000000a8acafadb6b1abb99edf0000b8bea8bffeffe3a9a1a1cd002620362160617d373f3f }

condition:
	$a0
}

        
