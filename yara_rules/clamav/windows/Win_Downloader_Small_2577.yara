rule Win_Downloader_Small_2577
{
strings:
	$a0 = { ca5f89e581ec9400000081ecfc0c000080eccf89e3b1978925fa4d4000a1596040000c1089836c050000a15560400089 }

condition:
	$a0
}

        
