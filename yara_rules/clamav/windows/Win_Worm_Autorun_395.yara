rule Win_Worm_Autorun_395
{
strings:
	$a0 = { 5b4175746f52756e5d[50-100]6f70656e203d[3-10]2e636d64[50-100]7368656c6c5c[15-20]203d20[3-10]2e636d64 }

condition:
	$a0
}

        
