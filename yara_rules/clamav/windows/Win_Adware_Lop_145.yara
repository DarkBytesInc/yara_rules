rule Win_Adware_Lop_145
{
strings:
	$a0 = { 5fffc7f40b815acc4eefda7d4b944d5fd9fa45d60f32aed5c23d96c2499f48ee7a43a5ee66eec83737fd7ed16984a290906eeb67170ef91953f6b111ff85b5cef1b5467334a6dee4c1b7e6ecf8095ff65b4118a1bccbb1a72aa5e325d53628cc3164 }

condition:
	$a0
}

        
