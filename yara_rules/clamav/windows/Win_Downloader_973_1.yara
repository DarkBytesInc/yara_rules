rule Win_Downloader_973_1
{
strings:
	$a0 = { 0bb5cc0ea46ae16026c9df49e5b0d8060360f9b382dfc16ce6db24a258838945a8efa8002350cb2f9bc061c0915d4ce672f53fff2ed47eeff691b20bb1e3bfa2f03ceda03e00eb0fb48840c2ccd0554b266b8c659f41ad22fa5d10b1 }

condition:
	$a0
}

        
