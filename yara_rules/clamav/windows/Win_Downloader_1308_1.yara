rule Win_Downloader_1308_1
{
strings:
	$a0 = { 9736f41adcb4b967466ebaca0ccf88cb72ffce9a45993cd28ff3bf8d205d33e1cfa6ef9fc1c83a493760bd2afb976bd162b0defdce4a33fe84c9abd2ce146e7f6c787b5ee691aaf8b0a80c829a0a4d1937b9fdb805178bdffa462b42e3510ad5fe4dcaf60f8e }

condition:
	$a0
}

        
