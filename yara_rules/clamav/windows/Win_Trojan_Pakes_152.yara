rule Win_Trojan_Pakes_152
{
strings:
	$a0 = { 714f503901111c8b3ebda27af02a6e14f14a503450303cc0c1a3dbf4d919140bfc2aa09878aca8ea50916400139e75306680c6201b70a102be6ec2509f8400fc2c367ba08452760e984a2a7e80a3114dfe6b024cf7ae75518349ccd35f40202321708441a3779fe04d7a635a1987cae01a95d97c4cc348aeed292a21fe54c510770408bc9986526c8d3834a0 }

condition:
	$a0
}

        