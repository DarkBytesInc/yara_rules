rule Win_Downloader_946_1
{
strings:
	$a0 = { eddde513c2494f7490265b84d0d7ec858d938289fb89814067e490cfa5db95cac5e2604cc63e09c43ef570e8473cca40cf5c8ad841ff05056faa8aa086c9fee9802dc9c1261244f6b950f64270b07b47c52dc3e8fccf4af7bdc832a5 }

condition:
	$a0
}

        
