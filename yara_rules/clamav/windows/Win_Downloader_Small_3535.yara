rule Win_Downloader_Small_3535
{
strings:
	$a0 = { cc33bfdecbcc33cdcbcb4bb3d4cfcbcb56082bdbcbcc4e8fdf585fefdfcccbcb1d7ecc215369f3d5cbcbcaa233cfcccbcb580fefdf1b33afdecbcc33efdfcbcc33cdcbcb4bb39acecbcb5817efef1cb310cacaca56f827dbcbcc4e8fe34f8b }

condition:
	$a0
}

        
