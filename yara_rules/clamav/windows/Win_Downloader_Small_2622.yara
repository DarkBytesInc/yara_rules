rule Win_Downloader_Small_2622
{
strings:
	$a0 = { 8d4ddce8031e00008d8dccfeffffe8f01b0000898554deffff6a0a8d95d8feffff5268446340008b8554deffff50681c5240006a00ff15d0414000c7858cdeffff01000000c645fc048d8db4feffffe8b11d0000c645fc028d4ddce89f1d0000 }

condition:
	$a0
}

        
