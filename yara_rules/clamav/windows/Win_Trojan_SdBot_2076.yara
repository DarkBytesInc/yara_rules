rule Win_Trojan_SdBot_2076
{
strings:
	$a0 = { cb0f3f0048ba906259c271da59ca5440735288da4b4a4b3f5c6703ef986e6082d6972950944e75ca8875f9a417a3a1332c5770c1f56b6aba10e26f9e8bf8d5e268ea3cfaf641ffa3b2fbafc7856f4e66d7d797d3f82dbda8ff4ccde05f17f3f8d2f8c0c320c108c2b940ca5f45d73d4b5b80e36223d0ac236fd4cbcaf3c4effef9d1e4447bbcf7a01e4dbad3 }

condition:
	$a0
}

        