rule Win_Trojan_SdBot_3669
{
strings:
	$a0 = { 4e062dd871f92d39b91db6f3ac01fe747b6a0d74c82048e8e7d31f413a725762b82fa7f573208a3b5f4e229d8e112fbc9f9f754fa6cc5ffb93f83544584ddf56c2701374c2245b0f1f44e5d374e5 }

condition:
	$a0
}

        
