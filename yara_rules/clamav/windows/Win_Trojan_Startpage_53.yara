rule Win_Trojan_Startpage_53
{
strings:
	$a0 = { 5f7326e4272b2345626f6e7965616f13f6112346b56973681fc9feb0d8660d1c47617973003b65db9fb9670d194861726463f3651bf2ff2cd868111f4c69766520566964656f76d8d91d6c115f765b4d }

condition:
	$a0
}

        