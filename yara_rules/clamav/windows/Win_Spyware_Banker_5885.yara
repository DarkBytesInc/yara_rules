rule Win_Spyware_Banker_5885
{
strings:
	$a0 = { be398c8b29a4079f455c305013862b2779eaeea03e337d8ba5c7ca34c87656760dd8aa86956e693e8af5f533279cdcb17b5c39ac3a96f1f15b72f671d35b921d232244b6 }

condition:
	$a0
}

        
