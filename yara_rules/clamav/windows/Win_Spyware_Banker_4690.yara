rule Win_Spyware_Banker_4690
{
strings:
	$a0 = { a953a80b75980b9b7a31cb58da20e514cf2a3f990d60cabdd6872a8ef0be385e4d6b0b1337ba4dd969201ccc6bd431f767064412497b8ad1948d9a50a59bbaf78fec7201dfb43b097389ea852e0b1e8c094dd7de15e462c0341f5f9e9df0a12cbcee }

condition:
	$a0
}

        
