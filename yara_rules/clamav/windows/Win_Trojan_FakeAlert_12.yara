rule Win_Trojan_FakeAlert_12
{
strings:
	$a0 = { 60ffffff01d081c0000a000029c0138560ffffff1385e8fdffff31c801c8298518feffff198550feffff8945c04801c885c0752fb9be040000198da0fdffff898d2cfeffffff8d3cfdffff318d40ffffff29c101c1038d8cfeffff81f94f080000730021 }

condition:
	$a0
}

        
