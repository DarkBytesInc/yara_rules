rule Win_Downloader_Zlob_1542
{
strings:
	$a0 = { 1899b0fd29d3aa104fb86b45f4d133b3b1cd5c26c03e984a4ee5458ef2ff73685b40846c2578677993e9b00516744b6a9c5b345de18b2acea96f893b2bc6531366efaeed4081b8dc6bde15ea69ff16858c }

condition:
	$a0
}

        
