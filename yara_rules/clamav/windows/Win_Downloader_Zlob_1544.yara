rule Win_Downloader_Zlob_1544
{
strings:
	$a0 = { 608b5c8e8f50616f9c2171a1d8a1c048b331da2b0f4cdd1c57ff92c5c17c5eebacf297a325d5960c4aa3473bc797d9217be95add54e493f03789bcd6a4fe623c16d243ce995c1c5a581b26aee5bc97a21c5c0bb4f8464d1542cc74dada0900e0c2ab7256 }

condition:
	$a0
}

        
