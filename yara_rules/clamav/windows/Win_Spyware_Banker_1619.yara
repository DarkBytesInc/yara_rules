rule Win_Spyware_Banker_1619
{
strings:
	$a0 = { 30186d99ccd6c2eb4ac0c05ec64b73747c5f68f0d82a4b2f6f6f922449156d26232432257e5d29527fe1d05d6e490d1425abd8aa0a75004e716eadbdf4718008c2a38f3cf1e941c2fe9dd5de18dcfef191338e6230c07d5fe4ad77e4ddae9cf1aaceb177ad8348f416edfcccf3be79cc4f308dab3bc8ef7dd13b720a0587894e2b1b2c8ba6bf76a2361aba2aa9771a92448316 }

condition:
	$a0
}

        