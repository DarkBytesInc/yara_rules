rule Win_Worm_Autorun_287
{
strings:
	$a0 = { 7300680065006c006c005c006f00700065006e005c0043006f006d006d0061006e0064003d006d00610065003100310063002e006500780065 }

condition:
	$a0
}

        