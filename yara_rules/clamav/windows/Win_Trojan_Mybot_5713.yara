rule Win_Trojan_Mybot_5713
{
strings:
	$a0 = { 6b8dc17d23c2274544f4da8312f10cdab60404ab6b17c8cb56ada2be33179b5860bad8836dd8bab59adf0579d67802a05b0e89445dd0a532ef598e0f20c0b3e6a02f0618adf2655801fb8286b172ff3fff3fc04d006c21746bd9 }

condition:
	$a0
}

        
