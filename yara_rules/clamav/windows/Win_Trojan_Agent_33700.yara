rule Win_Trojan_Agent_33700
{
strings:
	$a0 = { eb530ed4f90052bb2af6a52333be9441614ecee737d1a0fefcad79bfea60a00089a06b8502b0c0905a27f1af166678d87a4f449bbdcc51c95b6f6cc29ae1a7afa3dabb7bf68ad6d54c99f5d27c01a9cc80539bfeed12a516c9d01dce1d0bfb }

condition:
	$a0
}

        
