rule Win_Downloader_Small_2863
{
strings:
	$a0 = { 5ee08189a5915e6d41f9dc862211ff3e763db2a89a016c69f9c957e2c8c0de6ef1496b782b89e4f37feebc93dc2f7109e2168dbf9701888165dd84b9fc344ed4251060a449142e3db506e7516d98ea7bef57d37fce084187a238e86cb78cf2da600d30b9f0a00391fc6634314e8b45ede80b }

condition:
	$a0
}

        