rule Win_Downloader_Swizzor_592
{
strings:
	$a0 = { 480ad112454c604858dab37b9d9ec15605b49912c3149c6d68740bb216d47f88ce75a494b8f2db67c12acc32e4eb50f6eb6dbc590413800ee9b8ad23bc5657988d4b89ac928c14906cfad1d02ca60bcc0cc1284c438865e1ed2bbb159867722a6870df24a95e640124 }

condition:
	$a0
}

        