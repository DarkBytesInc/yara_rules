rule Win_Downloader_Dadobra_247
{
strings:
	$a0 = { 14e6c266e978ea6b56e2ed00a6704e88e0f7ee938ba2036ef3e4e208d34de9701a11b56c8ba96c02f1ac705486b8e80dceca5fa1231ab997453bee631fdb2734177e7ee38db1061f48f083b278e903f2a81181a514 }

condition:
	$a0
}

        
