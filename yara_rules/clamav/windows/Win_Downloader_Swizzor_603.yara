rule Win_Downloader_Swizzor_603
{
strings:
	$a0 = { 24d60ad5988bcac35b36d74b97f3eda673e32f3ef66e9712e98dd2f6be03d1a6efeac49596bdb381b4dae9d0b84c598fd3c21096ed1dc94609fbfb0e72395b59d5ef784b7d4ada9cd6af19feafa9d3580584569413e32b1d39b3aede96ada05058590dcd146e59c2ca }

condition:
	$a0
}

        
