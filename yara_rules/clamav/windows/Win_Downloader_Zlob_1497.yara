rule Win_Downloader_Zlob_1497
{
strings:
	$a0 = { 7f2e2aa17258a57064d42540b1960dd2663e85de1126d282da92e06ec698fd8d39d35a70e19ff52b438677ec797b39e72c8c76e4fd3f598e166889572da70b488561d7cee973ea7c58e725a346cb25472d5cdb178dbc4db68e4af8a5350861d874aadf23f56fa8276b133a1078d609de8a7a3622 }

condition:
	$a0
}

        