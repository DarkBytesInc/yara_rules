rule Win_Trojan_Sality_1064
{
strings:
	$a0 = { 8afc55554386da81f601263fa569c18afcf8b1f7c3188df39488e7f7c00ba24b5f19eb84dc76034784d5e85c00000088ee89cff380e2168bf60fbfc14af38ae003eb2aeb0fb6c933d288e1ffc98d3590904f7cf2ffc020d50fb7faf6c39981c22ef4ffff85e8c7c5f16395f281c2d30b00000fb6fa0faffffec0f6c45288f181 }

condition:
	$a0
}

        