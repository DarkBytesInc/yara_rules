rule Win_Trojan_Mybot_8455
{
strings:
	$a0 = { c0af3a4d741169fd3516dcae2b43d62d0a0d3e704ea1f08b89c38b0c00d7f19e4f38baae6ab2a606ab15a462ac6e3c5baa17226d6dab27439516d5b80d5f64c68b6e9b474f38453e80955d4f027b27f685cc846c06 }

condition:
	$a0
}

        
