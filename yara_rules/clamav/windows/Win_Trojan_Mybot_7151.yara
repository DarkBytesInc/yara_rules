rule Win_Trojan_Mybot_7151
{
strings:
	$a0 = { 56c429456acabcc465a0ed7a5f7978ac36b131208c951131d567aff0bb442da23195455d0dee0877e3dedd9b7e42b07e047641f11c37517d489ffd960ff81049979eae5467042f34b0fc2c789949039deb4c1952295f8b6b25469a6ee3b50f1c8c5132e7eec5ef2017c7a911211a87eb3aefd992a41485d352a89f4e3ff6e4dd4fdf07e288084aeaeae224ac }

condition:
	$a0
}

        