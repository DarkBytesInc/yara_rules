rule Win_Downloader_Banload_463
{
strings:
	$a0 = { 328ca58a7a15fe33fb1a7c9f6a8d3658b49d24556ed7d4906d6adf41108701c5da02ed7380f00b6cfec4fc8b9c439778c47c0767b5d3cd496205cb903df85df9c20a8d87289b5dc0459e1caadfe6a111bef3eb86 }

condition:
	$a0
}

        
