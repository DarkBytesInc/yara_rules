rule Win_Downloader_Small_2772
{
strings:
	$a0 = { 5a16a78c0c7a5b570da71fb378ec290f84429b03027afc8bb3c2c011b5d76a60527415faa72a248bc4de26d6ee9b21e8780353e80f476bbd618a710ad099da54c09c67360ffc4c3896cd7884d8ed6316c8a24105df43e5869f1699c88b3a70acdf20a8f88711ee84939192b2959318b42dcc }

condition:
	$a0
}

        