rule Win_Trojan_IRCBot_311
{
strings:
	$a0 = { 2ebcaa4a1048a796997de2c8a7417b56cb7b9891aa753cbba0bf3200e6b1bc3c166593d6b73dcbdadbe066388ec5d6d967b3b0a5a19f345188f906855eecd9ea2d01042dbdf02be80f641f2421982671e6f3924d9d164b }

condition:
	$a0
}

        
