rule Win_Downloader_2216_1
{
strings:
	$a0 = { e872ffffff56ffd0eb1064a1300000008b400c8b701cad8b40088bc88945088b413c8b7408788b450cc1 }
	$a1 = { 8d85b8fdffff6a02c745c03c000000897dc8c745cc4c4040008945d4897dd8897ddcc745c440000000e8eefcffff8d4dc051ffd085c0746e8b75f868f1cbf7ae53e8????ffff }

condition:
	$a0 and $a1
}

        
