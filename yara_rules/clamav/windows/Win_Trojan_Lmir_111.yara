rule Win_Trojan_Lmir_111
{
strings:
	$a0 = { 7e55f042726442940f118a1e1a4a8aecd5cf5a8c545064ad0dc6b9e125cc0e11e60a75134f998bcd37e8508417c0129087507474fc2ef948484654a68a0124a2453fef56d48ca2ca07abff12825e5c0023697232686f6f7e4970806b36c35c2a2e2a3d837d41332e0b022e8204e797272e6c6e6b8b51003a88c8ec2bb798a49ec484fadbdbbaff44d2175c519b4a885001c662ee6755 }

condition:
	$a0
}

        