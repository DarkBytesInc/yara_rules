rule Win_Spyware_Banker_3358
{
strings:
	$a0 = { 17dcbd5b3b71ebeb8a0cb62edfe2a44f355a6e035e3797412ae33d0dfe1b83d8597749db33369dac38074694eb49a9bea2cb1041e3b25f39ebc700fbd63b4395e0fc109477f7dbd07fe85bdd3fe822db5024dc6a97 }

condition:
	$a0
}

        
