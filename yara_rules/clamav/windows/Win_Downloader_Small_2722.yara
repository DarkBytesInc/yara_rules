rule Win_Downloader_Small_2722
{
strings:
	$a0 = { 6449c318555d8134ed735703fa8d85b80a1150ff959c2b2c3222ea13210ec32a7d2895b41a680110a66ab8d07572036c6d6f6e2e64b77aabb88e703a2f2d77028f1e726f }

condition:
	$a0
}

        
