rule Win_Downloader_Banload_248
{
strings:
	$a0 = { 95b1e206b730ef6594dc39a41535fd783220565bbc2d9e2d1e9e4ea13cfd79a0fd9057c6dde0f8b22301a7cfdf404ea3c9690b0ee0529c8ba39a4ba934595500c79d3eb7fb9dd70d53e30c7c83a21061da8cc2732f30388cb410 }

condition:
	$a0
}

        
