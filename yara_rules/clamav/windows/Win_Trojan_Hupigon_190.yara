rule Win_Trojan_Hupigon_190
{
strings:
	$a0 = { f60a1a323ec9541c7caefffbd18bbcf447cffa5cf31d3cf2da3f5dd5a53930bcf3c928075a68c3bc123fdf1b08442c5eedde4d40f8cea4dccf9eab65be781a8a807440ecdaf02b6e01ea37708e4fbfe9783f118a15277e71611f197521ff7561c999bfb6db240dd6c108ffe9b7d5 }

condition:
	$a0
}

        
