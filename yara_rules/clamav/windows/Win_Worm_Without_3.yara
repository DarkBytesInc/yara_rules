rule Win_Worm_Without_3
{
strings:
	$a0 = { 652e6174746163686d656e74732e616464202822633a5c6e6563726f2e6261742229 }

condition:
	$a0
}

        
