rule Win_Worm_Fujack_2
{
strings:
	$a0 = { a36bdc653fabdf922fca727b4f4fe110ff6851c5f3c6bb4e51fd071f99b0f92ecc3b28e492eb7881e03783561e14de72506446111844611184d33c8340f02e40dac7855c8e64f6b899d0c92507ce1dd240eef8e5518d117844498cbfed4e0e90f5e0b9d99a84e3261f5324f5c41cfd6a06699d51140153ce475f9461fe34decc586ef64d1318bf51672978d4ed0063431da29bff47ae }

condition:
	$a0
}

        