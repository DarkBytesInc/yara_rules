rule Win_Spyware_Banker_3501
{
strings:
	$a0 = { ca5ea1a12d1938e25ae02aba4e8c1e4948de4d1892d8c9876d69b8cf09c4539d465cc73731703637d2f9ef20191826b0bec8a281db1dafcddbf5681f1de1775dc91cb3ac7e0e8f6f8a13e45979a3bd3c9a02154eba878fca572a }

condition:
	$a0
}

        
