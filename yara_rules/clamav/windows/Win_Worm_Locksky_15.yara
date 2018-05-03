rule Win_Worm_Locksky_15
{
strings:
	$a0 = { fed0b6fc01d14ae94521f4fc82d94bf385a7b4fc01a23100ffd04bacfe5abc14b629b4fc8491c0d2577c3979fddb4b0351d0c1f4fef83704fe5dd0c7c75dd4aa51a23100f7d04bacfe5ab8031415a4bc01ac4c0375663979fdd34b0351d0c1f0e95bbcfc01aa74f3855f4b03fe7be771 }

condition:
	$a0
}

        
