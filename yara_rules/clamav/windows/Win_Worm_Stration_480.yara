rule Win_Worm_Stration_480
{
strings:
	$a0 = { 011b2a62b9ee2153230854ec82620db309a97a484dc5c49a34e849c78ae2cb4cf9028a0515a2b0e620ce8ddfb04529537eb5d4deeb1ae2d6398fa1cec1a4ccc08d17be5c6d45735396ec815e607711edf3030d301469 }

condition:
	$a0
}

        
