rule Win_Trojan_Trojan_397
{
strings:
	$a0 = { b2f579efe6453890ab0ae32a7d6831a1df2ed6ab8a85e952c0e3df23edd0d1143a8e97ae3df73e80ab4d3fd811d7f7b711097934a5814170fec74c1f99b6b0f6fdda940aee792ad7af5b7fecad3d08501e817e224f29abf121ec80643d6508baec1dfdcd40352ea1fb67cb89d501ba6009b50dd9859741c0 }

condition:
	$a0
}

        
