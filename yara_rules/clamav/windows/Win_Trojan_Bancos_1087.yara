rule Win_Trojan_Bancos_1087
{
strings:
	$a0 = { f92e66d24db7071bd238f8381af31cfbd3faa1bc1fef587df2112ffddade1d5a538510a370aa1a3b7ff277a04fe07c9362ea059ce2c3bdebf663c7cd86eee37e0ca734645e8043091f28595ed2ef5d036c62e25bfe9b13f9a06e3cd8375836 }

condition:
	$a0
}

        
