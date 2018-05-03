rule Doc_Downloader_Macro_27
{
strings:
	$a0 = { 7777772e686f7573656f6673756c74616e2e636f2e756b }
	$a1 = { 7777772e686f7573746f6e736261636b796172642e636f6d }

condition:
	$a0 and $a1
}

        
