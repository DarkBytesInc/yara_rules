rule Win_Downloader_Dadobra_239
{
strings:
	$a0 = { d7e12216a71babc086ff1266967eac27d0153da2140b9ad27e525da57da3b66bd8aac91002369f32889c3cc55db807ccd11e683d09314096153f6924ef924d3450b21efa6bcf081dbb4bdb9227de68019ac571914f }

condition:
	$a0
}

        
