rule Win_Downloader_1394_1
{
strings:
	$a0 = { a928e54f75c4c32c3d8aff02dc14143b8b4795a9eb40fb86cdb50c90293ea635c92696a57f29a27f9dc282cafc03915ad5d580cb24a6ab680a2c96d456b0cd5bfa63af71aac3f854c497497fb596e6ee4e3e8ab570775ec873c0abe78db9334eeb9d25 }

condition:
	$a0
}

        
