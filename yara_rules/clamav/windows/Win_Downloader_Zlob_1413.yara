rule Win_Downloader_Zlob_1413
{
strings:
	$a0 = { 328fd5dd34d57d53ee44873017b9d08b64a8a06848c9bcaf58b472d3f9ed41b97cd019aa286bb20a233e0889f175df4f1a067534afe25092bbb77ff30c22280dc5bbc0d1821f733e502eb28238446b5d0a8bbc3889aea5eec6a7dae07a18a8fcaef40b7e }

condition:
	$a0
}

        
