rule Win_Trojan_Hupigon_1364
{
strings:
	$a0 = { 818cdc98c7e134122da03572b431b73c3f07ac3814af7f959a9a8ed3519b07aaf97f1ccdc9651fa6b6e5f2f3ca0f2cb2768f7b8a2c2dd9352bc07820986f418a7413bc6bef7ca9d2508dc6b2daace4b004f45f85b938edbec2733143bbf4eae55801 }

condition:
	$a0
}

        
