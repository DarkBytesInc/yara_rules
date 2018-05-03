rule Win_Worm_Autorun_238
{
strings:
	$a0 = { 5b6175746f72756e5d[0-19]7368656c6c5c6175746f72756e5c636f6d6d616e64[0-67]2d6a767932647d2e766273 }

condition:
	$a0
}

        
