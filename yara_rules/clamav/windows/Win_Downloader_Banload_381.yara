rule Win_Downloader_Banload_381
{
strings:
	$a0 = { 45e6c41981d73b4d027dbcd562f49192b692dcc95426927b09fabf2c8ff36f050ee246b2f6a94f0c8a81e51286f5f53cd7811b7d14ac1549267ac3e29999c1f4adacdfc52f88cfa7d4028ab73fbfefa682bf3eba61dbcb1ff875bb90c877c27269731c98caae37ffda }

condition:
	$a0
}

        
