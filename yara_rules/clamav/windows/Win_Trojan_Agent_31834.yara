rule Win_Trojan_Agent_31834
{
strings:
	$a0 = { 57c47e9932c42c0bfb297a52bdfc7a249c6363a8c016276d773170b33520cb061e51d4afe5bbde3b276c47dd823b8a13197612a252b110cd621c1f3335c1e316d6a9919a2d85c87d64a2addea78fe13c4586dc472c903a18525104fabf260be40463eabd83b5b7f24818bf37f31eff64f719a4c21ba2fd8bd8a0949d8d359ea61a54239daa958ed8fdfef6d35fae01065ddfdd69bd22 }

condition:
	$a0
}

        