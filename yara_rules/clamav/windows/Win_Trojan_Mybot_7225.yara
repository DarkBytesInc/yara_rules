rule Win_Trojan_Mybot_7225
{
strings:
	$a0 = { 96ee9a2773071c9e19603004c0183e7a1f1d20c9076e60fc554e20ebd75d402edf916e12dc0d4400e125a80c94f2d054277f54a6fb42cb8a41a8ff60a1bf5a44bd20d0c8a9dbfb44f757e4b4b073 }

condition:
	$a0
}

        
