rule Win_Downloader_Zlob_1551
{
strings:
	$a0 = { d91e0f8c347b4bbff92f28be526419f2cd70fa6f43bb4474c5064966db65d33b44658dd500fa0f4cc57028dc4b26dab7ddb08b0a58d3d29d19624efd5ef83b582caacca6a4b8c0e5e11bc87920f0fee0b81b904be420bec88aa1e89db6bca9d7190a3ee84a3f04a5b49d112a4b897b513f92 }

condition:
	$a0
}

        
