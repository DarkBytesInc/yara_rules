rule Win_Downloader_Small_3437
{
strings:
	$a0 = { 935a3ce10218990e9ba15a825cb341a6c9db69f47794eb331c9acb2dc61f2abc415fd93f085a0d12d3e842ca630dd834d2cb6a8bdd6015c1ade9d8f23126452036ecf370900e317ee1bc6aa469c60f6f99c614b380 }

condition:
	$a0
}

        
