rule Win_Worm_Trewiz_1
{
strings:
	$a0 = { 6131332e6174746163686d656e74732e6164642022633a5c67616d652e62617422 }

condition:
	$a0
}

        
