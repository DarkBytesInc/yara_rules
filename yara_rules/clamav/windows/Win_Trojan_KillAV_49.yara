rule Win_Trojan_KillAV_49
{
strings:
	$a0 = { 20003100320037002e0030002e0030002e00310020007700770077002e007600690072007500730074006f00740061006c002e0063006f006d }

condition:
	$a0
}

        