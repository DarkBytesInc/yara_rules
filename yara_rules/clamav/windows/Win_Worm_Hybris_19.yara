rule Win_Worm_Hybris_19
{
strings:
	$a0 = { 742e7404740a53c5f88bf9cbdfc7f88afcb81d0d72c3ec4fa35547b8b0bab55447bdb6b0b854472e455845082f54d43f547c43db7ffdfffffff07bc0feffff7a36f07b46ffffff95fc97ffffff7faa1780feffff740fbff07b98feffff97fffffdff95bf006bdb }

condition:
	$a0
}

        
