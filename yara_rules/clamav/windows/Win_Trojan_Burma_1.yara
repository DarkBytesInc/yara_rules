rule Win_Trojan_Burma_1
{
strings:
	$a0 = { 3bd23bd2e84601b9190051e8080059e2f9b8004ccd21558bec83ec40b44732d28d76c0cd21ba6301e85c007327ba6901e85400ba6f01e84e00ba7501e84800ba }

condition:
	$a0
}

        
