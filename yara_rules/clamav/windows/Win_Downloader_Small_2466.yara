rule Win_Downloader_Small_2466
{
strings:
	$a0 = { a692becb3104295fbe92bec93d210c7a7e4f1b610e22f87c1029091e7b4f617f1d283f01af4f614d23be8a4f0c3814612d1835437a9775a85d9d6d9c291cd25a122632fa99ac815a45735d2a9ab19ceafc184a3f69b229ec97b4b996fcc899ef8d11d0c4f4086704bb8da211a99cb0c8339058ca0c9db7c5 }

condition:
	$a0
}

        