rule Win_Trojan_Mybot_7665
{
strings:
	$a0 = { 2927201adc32a006f9b82c6373d238f011e963f54a74865c70540249d8ce8b496c9ee6e659f2508132ed349e398238cbd52476edd43266159e75aa00105805345191ab74f1169d5a656314693ff9148e0a50b78125bf13db3e898da625ca2a4c28eab74c9fd0fcf39d52b8a02d87af8c69d26428ad82ba82d49283a0148a820d29975e94191d16f66fd1dd0a639934bc22da652ed28a }

condition:
	$a0
}

        