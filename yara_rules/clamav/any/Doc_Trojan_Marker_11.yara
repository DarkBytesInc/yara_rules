rule Doc_Trojan_Marker_11
{
strings:
	$a0 = { 6f6e7374204d61726b657242203d20223c2d20746869732069732061206d61726b657221206279206a6f6e68656865686520546865426573742d766572736932313278 }

condition:
	$a0
}

        