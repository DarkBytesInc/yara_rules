rule Win_Trojan_Killav_87
{
strings:
	$a0 = { 7562746c6c6a6d6d21304721304a4e214f66757173702f6679660e0b7562746c6c6a6d6d21304721304a4e2144706f7466626d }

condition:
	$a0
}

        