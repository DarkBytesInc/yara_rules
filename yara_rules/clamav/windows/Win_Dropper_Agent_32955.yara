rule Win_Dropper_Agent_32955
{
strings:
	$a0 = { e427cec7a1e9bc8e190b8cad7a77e8d6bd963d2335090cdd7fca8e247f1be2c15e17e0412f9f73eb40db0b499e6bedebebf3d8b970e73968cdca06d82fc4aa803f2915bc3d2f36310b4e053863d2efc5c2e941e416aad1939b1ee1dd9406f441a4067d40cc3ff808db2e4b0704d2c3a07c243c1fb208f77fe9bae3c82cda8791ce13aed1bd5911c80fe1b7aa }

condition:
	$a0
}

        