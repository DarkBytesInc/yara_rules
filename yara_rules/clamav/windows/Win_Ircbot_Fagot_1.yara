rule Win_Ircbot_Fagot_1
{
strings:
	$a0 = { 415653434845442e45584500000000ffffffff0c0000005746494e445633322e45584500000000ffffffff0a0000004e41565733322e4558450000ffffffff0c000000426c61636b4943452e65786500000000ffffffff35000000536f6674776172655c4d6963726f736f66745c49 }

condition:
	$a0
}

        