rule Win_Trojan_Delf_1037
{
strings:
	$a0 = { 0cbec243817c968ebc5a30ab5548520ee999b0746fdf4be1421f2382acd235d2efbf48ab626a6e09e0cfbfc74f77f21ac58401fc7ee45a258e71639cf783566dd82f8c817d01908c66c544dde35e29a71ff337aa7eb20e5647 }

condition:
	$a0
}

        
