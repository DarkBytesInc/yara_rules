rule Win_Downloader_Dadobra_193
{
strings:
	$a0 = { 3acf0e6f726403ff6c084361f95a5c13696e05055e0bc190840a065374721c5c16ac67900c075661c079429974e8670040acbe8b1b5800e8396e7c5b04203838f13c87c530342888355e009ec7a4e007544f626a656374f4e052cc72072304d38e410d7973c1b770086d14110f0a49d10c081d7266616365238b865bc00a236f174603ce4a1600cc83442404 }

condition:
	$a0
}

        