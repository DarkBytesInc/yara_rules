rule Win_Downloader_Banload_1335
{
strings:
	$a0 = { 75459d966fdc982b9e5e3956e32144eeac7d265469c66863fbec13bcdf77b2d9570955860851a871d3366557a8809e90859066f1ea6990d95916084c22fa810869e4f1ccba61a8faa5c7f6e64025d17c5320ecc203ddac1f020e2b970a8ea148e5c746640ca41634bcb1b11e5b122fa778c10722d1953b22 }

condition:
	$a0
}

        