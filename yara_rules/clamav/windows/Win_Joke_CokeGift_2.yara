rule Win_Joke_CokeGift_2
{
strings:
	$a0 = { d39577916b2076d45f41a0d95a6cdf616c66886d3e74d95de87aa469fea7d1ff22e8bc2c5f89332de46bd6c43f839ef5e8998932a005d86e177116c95cf44f1c408efd162888b32f498d91e203741b0e7b7b9bd0d2a8376f26387ca92ff29a3717a2813b }

condition:
	$a0
}

        