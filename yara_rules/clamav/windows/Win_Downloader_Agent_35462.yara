rule Win_Downloader_Agent_35462
{
strings:
	$a0 = { 416678436f6e74726f6c426172343273[0-10]5365446562756750726976696c656765 }

condition:
	$a0
}

        
