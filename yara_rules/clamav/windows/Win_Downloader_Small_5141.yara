rule Win_Downloader_Small_5141
{
strings:
	$a0 = { 72696a75616e612e63612f690d6765731c6fb8c3fded642e675d00b811010480789e81ec0c2fe3f97fbb565733db68e09304004b008d85c196b1fbf4feffff506104 }

condition:
	$a0
}

        
