rule Win_Trojan_Bancos_1216
{
strings:
	$a0 = { dd8377eca001aeb399e7ea1afd71f509397cdebc2358ce017a381e2db9f63a40c1b283b379042b5da60f734b6a6c7e0402de32cabf8c5524050c49dd99c2516a2ba38e9e7ed8831057aed2bced12d9efcfa027838c8afab5b37ac4e19bd0a4 }

condition:
	$a0
}

        
