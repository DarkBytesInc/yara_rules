rule Win_Downloader_JS_183
{
strings:
	$a0 = { 7372633d22687474703a2f2f696e7374616c6c2e787878746f6f6c6261722e636f6d2f697374 }

condition:
	$a0
}

        
