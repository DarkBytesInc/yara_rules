rule Win_Downloader_Small_1280
{
strings:
	$a0 = { 3f7c1b080308c1e80e80235c776d706c610e7965722e6e78bc005e6a0e59f3a431e871336874c4703a712f1e6272615c76ce2e642e6f876a70febffeba72aa312b85 }

condition:
	$a0
}

        
