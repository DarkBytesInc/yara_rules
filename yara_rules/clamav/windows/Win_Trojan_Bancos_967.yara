rule Win_Trojan_Bancos_967
{
strings:
	$a0 = { 2660233c8841f6b8fd220f85dd4b13fe58fd4153f26cf4e90bb2101a9cbcf1dd001549587a126d4483618539d4e5a7cf98e4e3923efd3d3ed29688846772dbd55685678bc7f1a82bacf68d433ccc }

condition:
	$a0
}

        
