rule Win_Trojan_Haxdoor_96
{
strings:
	$a0 = { 72631f68747470733a2f2f36a110bf38652d676f6c640a2f362f00dffd9dfd79776964a3323117686569675d193235b56637 }

condition:
	$a0
}

        
