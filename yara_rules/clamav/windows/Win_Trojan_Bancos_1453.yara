rule Win_Trojan_Bancos_1453
{
strings:
	$a0 = { 4148c5fcb1010ea0fbf25b1a435dafe4c9283cada6827408f2a8f5faea768f6a4df3bcc7405ae8619d7ca67219b59e484be7e4869ad6b6ba4324697d046d5aeff822dc69f4153f2e56460b75273908f79a2ac440f646189a8b }

condition:
	$a0
}

        
