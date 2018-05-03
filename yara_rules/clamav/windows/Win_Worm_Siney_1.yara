rule Win_Worm_Siney_1
{
strings:
	$a0 = { 68c4e844008d4db051ff158c104000c745fc4d000000c785d0feffff4cea4400c785c8feffff08000000b810000000e813bff9ff8bd48b85c8feffff89028b8dccfeffff894a048b85d0feffff8942088b8dd4feffff894a0c68d4e844008d55b0 }

condition:
	$a0
}

        
