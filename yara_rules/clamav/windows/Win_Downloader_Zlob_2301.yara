rule Win_Downloader_Zlob_2301
{
strings:
	$a0 = { eeddc8f837bed734e1a7b0ad1dbb5103386035779e60f622179b800cee5d4e07701efc01ed8918a7063fac07a8a15194daf9a33cb67bade959ec28e70413af3171004e84adc970b623ea1f9e350020e81fd39244db540b6bae2f }

condition:
	$a0
}

        
