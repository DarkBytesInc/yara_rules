rule Win_Trojan_Prorat_109
{
strings:
	$a0 = { a841a5b3ed6faab2267f5bdf3610e6f4b83686ee52dc82fa7805045a0c312855334ac9bc24b430b0018a25fef394cebf50119adb7621dde22c529ff891727b8e7039cbc21e8cc82261ba99e8c9ce1ac1baed0284ce47ee86edef674b8e295c4e3db9eb3de9cbbaa5a7a5307206e55b4baa359b50758c }

condition:
	$a0
}

        
