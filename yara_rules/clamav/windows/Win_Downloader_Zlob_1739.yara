rule Win_Downloader_Zlob_1739
{
strings:
	$a0 = { 0e918d01444f227ce113340a67cc51ad687d2dfcd5619f53c06c49fcac216aa7a7ada93879b4662f26a4eb612d128e60a80fb327ea6e7b684e75e79ef4b6e6b7910e773a834f79db7d4ac8630663 }

condition:
	$a0
}

        
