rule Win_Trojan_Bifrose_484
{
strings:
	$a0 = { 1fa0c9b3166232d6154f3c98bd144bfd862dde0f06fbf58328dfccd6289bc81f63824735deccd9297d5f23ec8ec23b8d8b9549c59e0d5940eb300a1b62cf848e6a4cef9af74fc1589def1ed089e071357b1d1425a4587d660422 }

condition:
	$a0
}

        
