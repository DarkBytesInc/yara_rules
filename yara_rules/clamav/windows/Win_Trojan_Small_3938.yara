rule Win_Trojan_Small_3938
{
strings:
	$a0 = { d5b83999ba38c392b409047ddd87c48c50f813ce38c0e17c507b8889dbe8afded1bfc48c50f82d7da762c4e65462c4e64ff7d91c6138c407497dc3f2555722daabbb4f9a0c08047da662c4e65062c4e6524fc350dce84973c6 }

condition:
	$a0
}

        