rule Win_Downloader_1244_1
{
strings:
	$a0 = { f9feffff7280ed78c685f5feffff7580f54cc685f2feffff6580f576c685f3feffff7480c9d6c685fcfeffff735580f15a83ec0880e10a8b8538ffffff8904248dbdf1feffff897c2404ff15405401105d89851ffaffff8b851ffaffffa394570110c68568fcffff74b69c80c224 }

condition:
	$a0
}

        
