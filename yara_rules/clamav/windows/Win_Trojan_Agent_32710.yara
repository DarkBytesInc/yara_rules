rule Win_Trojan_Agent_32710
{
strings:
	$a0 = { 19affa5fdae0740b40ad5e375e7cefebfdbfc50bc721880693f61f73453be87ccf5be7d1ffffff5b8474c0185fe75067f8fb049a0bc909a3cadbb2987133f1a6daaf6ff5ffff180538a308ad465f58224ff2ce1ef65d951c6a226c3607acfeffdffa1801c151ec482cee6a20590b70291bd91f38310b9774ae122fffffff97d0 }

condition:
	$a0
}

        
