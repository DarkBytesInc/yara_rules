rule Win_Downloader_Banload_662
{
strings:
	$a0 = { 3821dca99d24d7de7a244f7bc0b544332dcf15eed60af9d12f5aa6f27a7891dc8e20812c779d9920efe2f2aae958a1badaf199a42f4239c749c83892eb085bc2b690548e1045d85adc2ddf408e72eaa9810d2e1d73c0b3d06988 }

condition:
	$a0
}

        
