rule Win_Downloader_Zlob_1685
{
strings:
	$a0 = { f62b104e42e31038b95ddfd2c6756be277f7681f64e3b6b392535d97015a206d5ad6dd6d1a04fdd2e69d9c8f8c2e1f8487db96c689a60d6675afd2b4256261d0d35d62d889e1bff0dbf89b7cfada7074b77bbe2d46fdf9a9a4e8 }

condition:
	$a0
}

        
