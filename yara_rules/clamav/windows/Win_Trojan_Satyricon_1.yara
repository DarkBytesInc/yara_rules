rule Win_Trojan_Satyricon_1
{
strings:
	$a0 = { b4005589e5b800069a3005b40081ec000668801e9a8a02b400a32e028916300268801e9a8a02b400a332028916 }

condition:
	$a0
}

        
