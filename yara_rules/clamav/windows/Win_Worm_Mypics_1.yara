rule Win_Worm_Mypics_1
{
strings:
	$a0 = { c745fc02000000bab43740008d4d9ce8afafffff8d4580508d459c508b45088b00ff7508ff90f8060000 }

condition:
	$a0
}

        
