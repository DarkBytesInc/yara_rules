rule Win_Downloader_Swizzor_392
{
strings:
	$a0 = { ae9de6d121f2d07eca87ebd0ac55f7ed78b20c6b98b4e23fd535615b548fc17b247ac2231bf9d70124c4c730b4c82688a3d64ab2c84ccdfeb0b1bd8a88b0be7a5b4be457f1b8662fbcff710574ca5c257348e600e476157f52e4 }

condition:
	$a0
}

        
