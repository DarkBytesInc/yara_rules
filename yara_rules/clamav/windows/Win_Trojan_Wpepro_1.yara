rule Win_Trojan_Wpepro_1
{
strings:
	$a0 = { f44278715a70d3e896fa44ef940a65c361f3e46d292d0e14e10db703f8471eaed5a685ae2fc0acf201f09112d44bd8b7535d31de8c6552ba04c49cc5459e312e0768480dfe584d7e0bcdc592ec63d6cf10870475030b939501801eb05f6b46357bc1c0dbb24e12761966882835f695e30669e9eb7582a017228289d77a2b7426c3c41fc7b1ab75d7624bfef5 }

condition:
	$a0
}

        