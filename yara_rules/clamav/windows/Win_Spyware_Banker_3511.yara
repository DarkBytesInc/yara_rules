rule Win_Spyware_Banker_3511
{
strings:
	$a0 = { 3f9f79cddcc4d302a21af0fd3061c08653322b78bbcd2a1197c7453b46ff0ddc655bcdce159dfbbaf2f438c7c07406e33f034c05c83e5c2a8155f9e94e0e9bce829131df901fe7582e914434ac0b472c4ada659a749d75ed77ba }

condition:
	$a0
}

        
