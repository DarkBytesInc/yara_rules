rule Win_Spyware_Banker_2362
{
strings:
	$a0 = { f9bfc83f66c5e948e936c8aad75e4a0aba2fd08bba45b49a6679ffb62c3649f424a1ed69259a67b61e5b3ae18e5e1a883525666640aeef189326da17b288dd1c0588951e1cbfcb6ac62a0254c7e7abc56e6a41d1d9bfe2a247f49040090798239c90d51fd0693e1c3aafb9ec2dfc54ec36fd64c19848a4e38f51deccbf2ffaa90e4cc7b343a5b75e7b3aaa8cb1c78b9090222ec17e0e }

condition:
	$a0
}

        