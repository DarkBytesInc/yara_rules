rule Win_Downloader_Zlob_1514
{
strings:
	$a0 = { 0d59965654c5d3d7e1f6d493a92c63c33dca265e6df1bbd2de29c7e4168a0cf90091045d96c0b1b20b4939304292ed8fe8ce7d44686c533af1b3addccccd2136dd5bb81cf32d591391d66997c61bb604ea265de8b7e40a83bdb6d52da06a310b23f1bac283 }

condition:
	$a0
}

        
