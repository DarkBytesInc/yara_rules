rule Win_Downloader_1414_1
{
strings:
	$a0 = { 56566a02566a0168000000408d85e8feffff50ff15482040008bd883fbff7429568d45fc50ff75fc5753ff152c20400053ff155c204000e846fdffff8d85e8feffff50e8a6fdffff5957ff1528204000 }

condition:
	$a0
}

        