rule Win_Downloader_4398_1
{
strings:
	$a0 = { 41680a5b173176686616640f4c89adadea7e114385541144646a40ef123433c95434db5b7d17ec4d5c4ad3393bc2290c3b7bea56ebca290e78ddcc40916046c1 }

condition:
	$a0
}

        
