rule Win_Dropper_Agent_36283
{
strings:
	$a0 = { 616f70656e00446c6c526567697374657253657276657241006374666d6f6e2e65786500000000004144564150493332005348454c4c333200757365723332004b45524e454c333200d811400016d6d6c05066105db92cffe67a2ac6381abb7514bbf1af8a95dc29b909ad591209d0f6 }

condition:
	$a0
}

        