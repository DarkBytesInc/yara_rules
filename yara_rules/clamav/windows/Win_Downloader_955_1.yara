rule Win_Downloader_955_1
{
strings:
	$a0 = { 3cde87c802b50b4d4efe3e98ac2c01e205e7b6bd904b5d33f1a63555fecab66c51ee2c53b40547884b9fdbf61a5c99cf0dfff27db104ddda593ad30e1a6be2e3cf85a772c582ab6e07ffc2ced2c88dad2d09ff08f60ad9da45b8f7e5 }

condition:
	$a0
}

        
