rule Win_Trojan_Hupigon_688
{
strings:
	$a0 = { 82c9cd84367287c498ec4368655360f113c172557be35b4b504751744ca43fad27d71f105c3f793a26f98586f2ae9124ea312fb80316f4e36e213bee8d784abfa8 }

condition:
	$a0
}

        
