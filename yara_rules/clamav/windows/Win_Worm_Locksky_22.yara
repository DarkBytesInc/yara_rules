rule Win_Worm_Locksky_22
{
strings:
	$a0 = { 490df7bffd2c4c1ef1f7fde435e3ed64fce96fa3fd74b5caefbc0bcbf947dea1848f3f746528f6cb613647087c48d187ec303bfe2fc017f9ba9ab3610c3ed34c9dc166b399d0bfd7194c4554bde4cfbf2dba6321424a2f0c2f1d9187192735a7 }

condition:
	$a0
}

        
