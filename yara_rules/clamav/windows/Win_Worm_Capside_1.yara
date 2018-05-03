rule Win_Worm_Capside_1
{
strings:
	$a0 = { b9805b9480bb87891894ec1f4361707369646507d45a24da0df450c0400de9868d5a22abce630a2ed49cdba8e0472017 }

condition:
	$a0
}

        
