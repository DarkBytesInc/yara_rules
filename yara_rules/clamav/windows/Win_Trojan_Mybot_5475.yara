rule Win_Trojan_Mybot_5475
{
strings:
	$a0 = { 5caa756ec9ae1ad97236a533826216516a48c9f3cafce1a14106976c8ebe79b24afff7b0b73f2115b3b251d4714a6657d009d67ad4cdb8bfe98da8564de031fcee9a2e4eaebb66a6b88ed9e1413b2cacf256d474fda0d7ccac32c67bbc1c326b5e3d932a0f2b0024b5 }

condition:
	$a0
}

        
