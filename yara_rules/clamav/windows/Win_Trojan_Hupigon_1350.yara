rule Win_Trojan_Hupigon_1350
{
strings:
	$a0 = { 069aece44aac7feacd14e4abbd722bc29c315f92630aaf86007bab7241d3b3435647687a4c250efff4c0e8dcf3fbc0598f3fb0a3302b0b4b45f9b0abbe2260bc0687a7bb9a44345f0b75ffcf0150e2da790bd157edcc8557cb7c285ef49578c8b314 }

condition:
	$a0
}

        
