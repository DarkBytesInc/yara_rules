rule Win_Trojan_SdBot_3917
{
strings:
	$a0 = { c48e7f74896841826f1e03d0bef74c8f73e1a91a47c6766118f3c6900cbe2c3f06b20a3f32359a8876d86331c470dfaea74abb3b4ad7fdd4f7fd5df10bca9ec02c772bcbb9d8e85028d44e7f54c5bd75189f31cd8bec8f4cc0627fad }

condition:
	$a0
}

        
