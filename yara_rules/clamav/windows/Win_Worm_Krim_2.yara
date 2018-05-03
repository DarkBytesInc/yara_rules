rule Win_Worm_Krim_2
{
strings:
	$a0 = { 6d616c652e6174746163686d656e74732e616464202822633a5c616d6f72652e6261742229 }

condition:
	$a0
}

        
