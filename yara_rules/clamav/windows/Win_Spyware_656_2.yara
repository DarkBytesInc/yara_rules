rule Win_Spyware_656_2
{
strings:
	$a0 = { e1146c0453af720eaae2ec272bc0ab4eba0ef240db6fc567b1779d0b52198bc19045110a985822d092e4ba661e6583ab6a6e362e6fd4c2d16ae780f37ba5dba84aeb3b095d16ed4fc44e30c5e5dfbe7354ad3d1c9050ac2b208cd49aad70c0352948b923353911e93905abf613f6 }

condition:
	$a0
}

        