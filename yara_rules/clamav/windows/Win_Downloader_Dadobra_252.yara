rule Win_Downloader_Dadobra_252
{
strings:
	$a0 = { ac17664f4f0948df52720a0ae55c18bcd8723710d5e6bf9789ba1fec5166e3733c5da027b55160b4a0a498bbf76bf50a546cb30c445cc2cf22006d8a579ddbf287d9032dbee0c004b966ee73654bff70ad4f5ecac7 }

condition:
	$a0
}

        
