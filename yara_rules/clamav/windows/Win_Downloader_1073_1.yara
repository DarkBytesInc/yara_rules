rule Win_Downloader_1073_1
{
strings:
	$a0 = { ecd960c5b1e821d2ddb58fd90e73bf0515a0eb64b633ded81fb1ff68f688d380e5ebe8f38ad33d106693d0733cb61abe30199b61c15f0bb3e80b8e8ea7270a21b5910bd0012e8a1b2af4e9c540cc1e5235ca3546a342d02e5a8c5bb0 }

condition:
	$a0
}

        
