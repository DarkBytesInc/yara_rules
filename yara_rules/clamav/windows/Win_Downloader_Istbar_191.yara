rule Win_Downloader_Istbar_191
{
strings:
	$a0 = { 42786c00739b66d9c0417c3cd8401b03edffffa66470755837516257543547646e4d43653755553513ffffffff53306176645841 }

condition:
	$a0
}

        
