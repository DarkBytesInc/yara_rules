rule Win_Downloader_Small_3385
{
strings:
	$a0 = { a05b9d3b9385824556ff33a75c8812dc4d4d4dd3a71c8087581490cbc5c932b817e5ae83ead2a0a1b3e5061f46ed26a3d8e95a35ec6e7845c684812e276403494d8f77a693 }

condition:
	$a0
}

        
