rule Win_Adware_Mediaget_5
{
strings:
	$a0 = { 776e6c6f61640000006d656469616765742d696e7374616c6c65722d322f62696e61726965732f646f776e6c6f61642e7068703f613d6d656469616765742d6c6962000000000000006d656469616765742d696e7374 }

condition:
	$a0
}

        