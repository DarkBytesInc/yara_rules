rule Win_Downloader_Delf_914
{
strings:
	$a0 = { ccc8efbe1cd45b5bf729a3fde90dfe2efbed290fd11696a76dbb43a1987446f3874568a79e024cb44a0d3014eb66f315b202bbe803804bc850a3cde52e27cb349ca610f9000cc2c4c828dee54c20f4e85acb4e5eed5f374f4fcca54510344908fcf0666c }

condition:
	$a0
}

        
