rule Win_Spyware_Banker_3099
{
strings:
	$a0 = { 04ca57702e6541626be6c411e3a8c23769f98410021038781489cedd951c6afbb9126f24bf66e3ad8e1c65af5861ed9b2c7ae71bc821bf69b475091bc5a2a5b3ba3d6cc413bf92ba2eb58023b594a035bdcd16d0cbeab58cd6cdb70ef42708292e41b7ebf61f2ddc2545c7192b786c766a64bf32c3c886b4e8a4b57c85679f63ed1ee63e86461362d2ddaf07 }

condition:
	$a0
}

        