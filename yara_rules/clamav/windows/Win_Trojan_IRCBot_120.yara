rule Win_Trojan_IRCBot_120
{
strings:
	$a0 = { 6864b2001051e8a43100008d7c245083c9ff33c083c420f2ae8b84243c0200006a00f7d1498d542434515250ff154ca10010 }

condition:
	$a0
}

        