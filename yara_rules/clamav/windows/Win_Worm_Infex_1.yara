rule Win_Worm_Infex_1
{
strings:
	$a0 = { 6672696e2e776f726d00496e6665780000496e666578000001000100781840000000000070304000ffffffff00000000fc1840001050400000000000e8010018490000000000000000000000cc12400001000000942a }

condition:
	$a0
}

        