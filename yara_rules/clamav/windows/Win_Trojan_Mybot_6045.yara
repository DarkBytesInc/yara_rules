rule Win_Trojan_Mybot_6045
{
strings:
	$a0 = { fd8068b0d2d1098a6fecda8a14798ba79e859f80a7fe0f860c9223842252504415686c3d2332ad62eb1b1915286e62ba460e27579af1948d4b108cd20b5f66ac10c9a8642a21fd6526d51f7de5fe4fc2a4fe1056c72545b4ac2f0ed4d22df0b5755fd8b9a6e2a4fd65ef44a47d0d241ebb21548b776e }

condition:
	$a0
}

        