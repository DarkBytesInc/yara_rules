rule Win_Trojan_Fakealert_47
{
strings:
	$a0 = { 909090c785f8fdffff00000000c785f4fdffff000100008d85f4fdffff508d8500ffffff508d85f8fdffff506a0068df310010ffb5fcfdffffe8c10b000083f800752effb5fcfdffffe8930b00006a016a006a008d8500ffffff508d0525320010506a00ff15ec320010 }

condition:
	$a0
}

        
