rule Win_Trojan_Likha_2
{
strings:
	$a0 = { e31f6a43334b838d5b438d0a232b5333f3838d32831383c3835b8df3838d62835b436b836d8d5068696c697070696e65 }

condition:
	$a0
}

        
