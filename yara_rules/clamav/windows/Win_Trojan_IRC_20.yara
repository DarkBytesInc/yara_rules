rule Win_Trojan_IRC_20
{
strings:
	$a0 = { 623133206279205b73645d0061620061626f75740069006964006231332072656164792e20557020256464202564682025646d2e0073007374617475730051554954203a25730d0a0051554954203a6c61746572 }

condition:
	$a0
}

        