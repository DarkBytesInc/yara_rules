rule Win_Downloader_Swizzor_510
{
strings:
	$a0 = { d8c20d76ad0d0bef43107ca24c275bef4103f0fe8e93830bd8a57603ec7d1acf0e13f88f02c8db363f98d5b7e983cde33db452efe544495cb82277179d774fa32a474650528805acfcf161fc27ac8962c51cb4398baa8cabb18dde9c4e3618ae75e6493fce4a9dab2d }

condition:
	$a0
}

        
