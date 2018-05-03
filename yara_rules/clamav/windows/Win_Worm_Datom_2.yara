rule Win_Worm_Datom_2
{
strings:
	$a0 = { 4eec517213838d5787c65ada5cca7e5e8f6080920394758597199afa999c3f4c5340114222634406f94709fd4a9bfe8bfd10f141a268b93817a7e80a7d1e1b6d }

condition:
	$a0
}

        
