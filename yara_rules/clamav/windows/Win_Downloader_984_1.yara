rule Win_Downloader_984_1
{
strings:
	$a0 = { b629e9fbd5c4f7f2372ac9f7231b2d8c22671088cff1ab6d69b60020bf546b1624234f053072cbf77c75ceb031466764cc875671dacb5ff2b9ecf600e235c6b080e244bfcf497e90f7ee9e80f266e8fde8b92c659afddc0dbbe1f841 }

condition:
	$a0
}

        
