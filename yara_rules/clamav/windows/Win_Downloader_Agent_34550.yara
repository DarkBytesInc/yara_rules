rule Win_Downloader_Agent_34550
{
strings:
	$a0 = { 85db39db39c085db39d239c04039c085db85c039c98a4c06ff80f12b32ca80f12b884c06ff39db85c039c081fa????????7d1139c039db85c985c039d24239d239dbeb1d39d285c039d285c085db85dbba????????85c939c985db85c939db85db39d239c039c93d????????7c92 }

condition:
	$a0
}

        
