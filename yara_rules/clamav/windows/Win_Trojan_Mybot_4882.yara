rule Win_Trojan_Mybot_4882
{
strings:
	$a0 = { 03607a0441c3efb1df55c867a8ee8e006e3179be69468cb30061cb1a8366bca0d2006f2536e268529577000ccc03470bbbb9160002222f260555be3b1fbac528c0bdb2925ab42b00046ab35ca7ffd7c20031cfd0b58b9ed92c071daede5bb0e0649b26f20063ec9ca36a750a93076d02a90609b03f360eeb038567077213578005824a00bf95147ab8e2ae2b00b17b381bb60c9b8e00 }

condition:
	$a0
}

        