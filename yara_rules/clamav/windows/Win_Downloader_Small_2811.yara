rule Win_Downloader_Small_2811
{
strings:
	$a0 = { c7156fc436b4fc3ffa9f3a2c20b4bea01b1f5ce6da0debec2d7fe3bc652dcb2daa47e3357187490e5643e20cecb407ec0d1f3c8fafc1e2c1941881ec77e9e6e1aa8b5043ab9bdd6414b4cfe4cbe9137f1cdf3f00755f72157950f9e5c06104092b5c79d95a8236e15f50ec0eb17505c9fb1c }

condition:
	$a0
}

        
