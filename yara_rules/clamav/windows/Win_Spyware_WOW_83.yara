rule Win_Spyware_WOW_83
{
strings:
	$a0 = { 64e33251eb46b2f37c32aa8a3a050b4c8deb51db2d1097e8339d96e76a6fd8a1ba73434879045f2955e2b46e58d4abd8232d82775f6762877395636a1b0dadb63e3797f8235fd9747202710c5cca8568086e17e19ed800f422d1212e74930739d3250fee6d7b97ccc1f5cafecfb0418ab2bb942fc23cb24c753e8a0af01f66809f4eb12856c238ff14482fdc }

condition:
	$a0
}

        