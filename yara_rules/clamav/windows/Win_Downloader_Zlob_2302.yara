rule Win_Downloader_Zlob_2302
{
strings:
	$a0 = { e9110ee49876830016f68a8e4e2ed32ddb8b07fcc2128cdb9efd9eac7588fa7ea2bfabd85f40d433f8b52cc680ddb396e41b527ed39ad184d82461384d726b4d52397f93f40a1a26caab4cb32269007d2cf417d3a18a297af3dd }

condition:
	$a0
}

        
