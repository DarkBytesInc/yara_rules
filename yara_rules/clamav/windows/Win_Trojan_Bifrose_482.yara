rule Win_Trojan_Bifrose_482
{
strings:
	$a0 = { fe336cabb62986ecd54ec414a132f253f5c2f64acd38675cbe8e21cf2e2c9795c992f107b1e26428c6aecdb4cd7c4ad1dca6f455d6c48fbe744e17d75f2aaef9c3e70e4f876702bb5214fc2569cfb63e3131c358af7c0b0dd201 }

condition:
	$a0
}

        
