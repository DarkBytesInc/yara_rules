rule Win_Trojan_Lmir_237
{
strings:
	$a0 = { bb0a0054e8055b0000c467f644242c0174050fb75c24308bc379d1ba60445bc3d0e7e7c7f2ccc8c4e7e7e7e7c0bcb8b4040059605356bed075833e00753a68440680d809e66a00cb8bc885c9820be404750533c05ea1cc00001d0b8901890d33d28bc203c08d44c1048b1e89188beb020089064283fa6475ec8b068b10891690896bbd36a4400499a032818b }

condition:
	$a0
}

        