rule Win_Downloader_Small_689
{
strings:
	$a0 = { 10f3a58d3d40400010893d38400010595f5eff548f045d5e8b5d0c09c0742878348b7b0853e83affffff83c4048d6b105653 }
	$a1 = { 6f74255c33392e65786500687474 }

condition:
	$a0 and $a1
}

        
