rule Win_Downloader_Zlob_1713
{
strings:
	$a0 = { 2c9a4d9c037a9f1e6f1de8d32fe843d37afc791d8626feb04ec77df7a7a0e1b1e91480468050b27d90a43872a8033e3e17e5a21a4f42d6e892ce06758f493ef8a33f4ec293420ebe0c87cb8a5404cbeec0e597818deadd8742fa }

condition:
	$a0
}

        
