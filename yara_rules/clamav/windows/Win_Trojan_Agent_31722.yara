rule Win_Trojan_Agent_31722
{
strings:
	$a0 = { cb5f33a5a2020f28d9176710848a5b72dee881c3fcdaf3596ee5e85b2159a3d8e04c0f0dab5bc235e8f4f2da59dc360364b27620858ef14d36075b049748baf330c86fac000a0ffae8b8bac0c0fb1d43eb1a15e18a0e3bec12cb1aa10bf8fab3388909a5 }

condition:
	$a0
}

        
