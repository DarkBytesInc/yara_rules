rule Win_Trojan__1368_0006_000_1
{
strings:
	$a0 = { 2d03002e8986d901b4408d960401b9e10090cd21b80042e8d9ffb4408d96d801b90400cd21e80e00 }

condition:
	$a0
}

        
