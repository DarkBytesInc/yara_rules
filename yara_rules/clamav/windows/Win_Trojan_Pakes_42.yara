rule Win_Trojan_Pakes_42
{
strings:
	$a0 = { e25b37720afe62f7be93eac08b39ecb7bd3b39c32069fa4231487d1723342c40dc5a0c2b1a119e304afddaedc3dd887b99189d8addbce705974557071110f0a2ddb4a9b89ff0ddb2ae3b876bb17a0319d27b9dcb455c0fcacf4c024119dee804a4249c0f2200fbbac4c538b5517a6008566f941dc10a1516f492bbf61f }

condition:
	$a0
}

        