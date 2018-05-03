rule Win_Proxy_Lager_85
{
strings:
	$a0 = { 5255a28d69c118e2c8cc7d3d414adb9d80cc2a82dbcc64270b27df2ba33019c71410ab23b20439cee080b08c130bca85e1fea9c7f87b3fa6dfe259abcec5a811c49bb1f4 }

condition:
	$a0
}

        
