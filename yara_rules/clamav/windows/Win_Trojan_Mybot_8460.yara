rule Win_Trojan_Mybot_8460
{
strings:
	$a0 = { 76ad93f5e79b3d4840f1b37924e9b78a3f7cc174aa77bbeeae51d577d215cd4b12cf59853eedf8be08de40f03ac96cab4cd6fa58e20fba2a8294e9ef9cbb8353017340b6b782bb44ccb8328d3e75b964641e63a61a }

condition:
	$a0
}

        
