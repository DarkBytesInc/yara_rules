rule Win_Trojan_SdBot_1785
{
strings:
	$a0 = { d1d20e8834d5432d859c2f0cf545bac2a7ccb302c7a7644f6d948ef6b4294fae31d1df7129549bee3a743a238232ceda0e031273c86461fb4d99f1194fc81a0ff5a540d8bbd4b633c469b11510fe4d549456bd65d5a7ebea02f09bb0d2a68ead13dc }

condition:
	$a0
}

        
