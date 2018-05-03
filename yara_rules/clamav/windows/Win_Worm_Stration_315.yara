rule Win_Worm_Stration_315
{
strings:
	$a0 = { 28437901994b75c1e81f68afbfd869c885526326f05ec56d1ba6a6a4fec2cb99251a475ae1967e325ec9aaebc5495f01b9a778796e9b7088815cb1c65d989931 }

condition:
	$a0
}

        
