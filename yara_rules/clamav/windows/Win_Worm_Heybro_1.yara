rule Win_Worm_Heybro_1
{
strings:
	$a0 = { 427965206e6f772e2e2e221376362e6174746163686d656e74732e616464 }

condition:
	$a0
}

        
