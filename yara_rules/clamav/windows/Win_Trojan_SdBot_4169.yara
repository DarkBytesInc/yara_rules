rule Win_Trojan_SdBot_4169
{
strings:
	$a0 = { d1cfd6c16671922ee39f2d7401b08d1d7d6a362ba3e20217c4e989c8339d765b8c01659e486e2273c7e48d146cc1df5279284c39e4b35233b57e90eed9c6e8daa79b61c45ee71758a08fcaf6d1153bb92d30138a8c7762c0a6bd505f4b22d4f2b3b9451faa3561d7dd74830e1160cef1fbaa0ec9c11698d0c6e8027428844c30 }

condition:
	$a0
}

        