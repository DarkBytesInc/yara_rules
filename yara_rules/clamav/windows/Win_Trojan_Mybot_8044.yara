rule Win_Trojan_Mybot_8044
{
strings:
	$a0 = { 1d5125f5a30964f9fb27978c819b8cebd89f6d913bdac38a43521c1b70ec39db6511c350d112692bd82156689e524a412e7e6deb6e286c184f720ce33962fc5081c13075ac17eaeb62e19f52395286bee5417b45a8c2bc4ece8acacd827e2dad907f47ccc058d544e9bf0b3a7fe66e8d69f6d8ac28afc7c331661c445d2cd8aa94785651a64d78444458 }

condition:
	$a0
}

        