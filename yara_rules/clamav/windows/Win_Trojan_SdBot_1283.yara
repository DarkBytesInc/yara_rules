rule Win_Trojan_SdBot_1283
{
strings:
	$a0 = { e46276a06e4a673595c974965579dac3166a306e380c08ff6c19b09ac64645ce51808395519e3b78ed6a0563326302bf876929a940d1221c6e1472c179b6def492c928662f2d18d104975ec951277a4dc56630de47ce4823edcb8d5eedf87fae511c71c21155dcd462d6754a72e33a8301b8f3cb8fb840e97e520ce346db4b9b3acce87ae9ee712782f3afaf52ba9928b63871bbc250 }

condition:
	$a0
}

        