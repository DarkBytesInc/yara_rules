rule Win_Downloader_BAT_42
{
strings:
	$a0 = { 757365722031203120200d0a67657420626c696e672e65786520200d0a717569742020 }

condition:
	$a0
}

        
