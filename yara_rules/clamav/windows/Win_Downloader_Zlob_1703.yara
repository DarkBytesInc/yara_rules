rule Win_Downloader_Zlob_1703
{
strings:
	$a0 = { bae8a96119a48d42c3f073c683d698a7cca20441ae9fcfec0c58267877504c5b1ac8579de695ce068b34f7646af6f5914e6707b534872bee777475bdcfd81631b9b1ffc4cd4625ae748bb2821cdc3a65de198edfec6bbaa7ef0c }

condition:
	$a0
}

        
