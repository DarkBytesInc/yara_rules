rule Win_Trojan_DNSChanger_144
{
strings:
	$a0 = { b03cd31e32e6d636348bf3bff6ba1093ad8e1c2eb8c6d636c04a5a36b1c661b3a502d2aa2daf2d3db1c65af6250241383e4d173bb1c629890150ef3527c3d6ab9dc6ec6ec206d786b0dc8e46f1c68f60fb06d7ee350e1736dc8e2886071ed6abadaf6a31 }

condition:
	$a0
}

        
