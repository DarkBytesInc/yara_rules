rule Win_Downloader_4893_1
{
strings:
	$a0 = { 7340b8298a1415e8acb4ffffb8158b1415e8cab4ffff803d5db6141500740fb8e8a01415baf58e1415e832b7ffffe80df2ffffe80cf3ffffe8effaffffe84af7ffff33c05a595964891068e88e1415c3e9dfb0ffffebf85dc3000000ffffffff0200000030780000687474703a2f2f }

condition:
	$a0
}

        
