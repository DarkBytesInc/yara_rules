rule Win_Trojan_Hacdef_98
{
strings:
	$a0 = { 673d00133906a751ac851f95940241e1b73eaf81bb3233e3e708a00c969312ee73edab77b6b190f7c907e0543830f8954de63131b1d1c8dcd62ac3487c6e1e477ec17546adec089bc126f17cefe950c002972e61924dfa86143dacf8a1db0aa76b8482beeb5dfed0ae084540e2d2357f3740a36eb10e7c8daaf2015a19a3315c00ee9783f729b1c2c4c7308ef05954d80d99fe4de8 }

condition:
	$a0
}

        