rule Win_Trojan_PcClient_53
{
strings:
	$a0 = { 9c60e8000000005d83d5f98d8ddcfdffff8039010f8442020000c601018bc52b8570fdffff898570fdffff1185a0fdffff8db5e4fdffff110655566a40680010000068001000006a00ff9508feffff85c00f8469030000898598fdffffe8000000005bb9 }

condition:
	$a0
}

        