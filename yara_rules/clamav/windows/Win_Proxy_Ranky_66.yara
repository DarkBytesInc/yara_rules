rule Win_Proxy_Ranky_66
{
strings:
	$a0 = { df894c8e56bc5be0856d32f14da26a1786ad64a8a1b85699674dc6bac69d2e4654cc253f9aad651f594de05e6c9e8d64567cf31b6d607abc4dc0cd5eb981fe26a5592dfdf8fc7710a35cb242ec5c337f13b3c764a07a769f283197348eee6b8d6bd7a482 }

condition:
	$a0
}

        
