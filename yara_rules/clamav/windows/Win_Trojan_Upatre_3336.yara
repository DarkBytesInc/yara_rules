rule Win_Trojan_Upatre_3336
{
strings:
	$a0 = { e9172a0000ff152c4040000020076600645e64000aac001368c072110d0075c43d332e003e8f00550b5f600022006b20760a0000300000efb11000002e57646422742000316804fe79830a0022741a1725f800003d616ce9a845cc006e5002036c8929006f70fcc315000000696d28560f406c0073650d566e203a007254940b }

condition:
	$a0
}

        