rule Win_Downloader_Swizzor_418
{
strings:
	$a0 = { 925c25d8fca7c82555116ad94470a858046b3f45aaa859cdba304e9cd1d347eab22dbe2b0abd14d9cd2df7907b64be303fe339ba8f7e92d4746d60376392265219ffdba0a913618699b3d5c6c906731bfb9b544ab5cda97ac87f }

condition:
	$a0
}

        
