rule Win_Downloader_Small_894
{
strings:
	$a0 = { 7220b9df36400051e80000011e8bd883f301e80000029e85c074008bc35bc9c20800bbfd104000eb05bb061140008bc3bb01000000ffe0 }

condition:
	$a0
}

        
