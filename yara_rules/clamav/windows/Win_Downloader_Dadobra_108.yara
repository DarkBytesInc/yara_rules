rule Win_Downloader_Dadobra_108
{
strings:
	$a0 = { 512f9720c41dfc1e4497a8ab302e30ef07300a8ca716f2f86dcdf2bdfa402273401c104806b0210e56559e9a061a3ba607d1090cd61de44818a07d1843b9160c308ccc61315182080d5569ebb453b47f28e8718f73cb6ab0b67d8cea5a3b3ed02c890b126e7486040f465fc8e6fdb56b6579734a3c4c2e0500113d22a538247b6475855c1e9cebfce62da4203c211d2037ca063dae48 }

condition:
	$a0
}

        