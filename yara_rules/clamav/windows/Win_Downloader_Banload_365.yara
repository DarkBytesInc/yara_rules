rule Win_Downloader_Banload_365
{
strings:
	$a0 = { 1465bfbf7ccea51b3e694fb323695df14fe8fcbffb767468f1a14b788941cf809cffcf822ce98b8b203db7947b36055d43cbef908ebc1b8312236b9307f267acdd97a294f6bbbf7cc48370126a723e1823136dca2fa8f7380b17fb118aaa7275558dfd1ea61185e0aa }

condition:
	$a0
}

        
