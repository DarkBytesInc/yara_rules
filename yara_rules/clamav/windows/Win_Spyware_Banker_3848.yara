rule Win_Spyware_Banker_3848
{
strings:
	$a0 = { 26ded8947679fcef09e5f23da2405e5444b000e0b540e7e048b04859a21e42f3f0861931e5346c8153ef0ea89bdc1c0c5f6dca49172a4ccd6b46e78f9f3e9b57575edc86cea3ec7ae5283c383158262c3aa890960b8bc51e743a1e6da21471c342a5e3a9c3aee77d1867cc55e263a002fdbe213b87700d6b8805eb522e3bd7ab3006e00baaffe37026edbd04 }

condition:
	$a0
}

        