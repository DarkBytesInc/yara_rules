rule Win_Trojan_Hupigon_487
{
strings:
	$a0 = { d2d7b0b49e91fe5eeb960b7b2967c33756b37b35837cc8817cdd4cffd7d92b3e6786d1d2c89e24cde5dd03c8f250270058b49703c3106b459a3eb01dd2f86bd65b421965f1686526d3fb2a8bb2afee6e9478259f1d91ba0c94f33c6ba9f3bd1b0bebd93d }

condition:
	$a0
}

        
