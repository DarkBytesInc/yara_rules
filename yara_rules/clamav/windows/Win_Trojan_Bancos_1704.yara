rule Win_Trojan_Bancos_1704
{
strings:
	$a0 = { f761ce65f89e1e28c414cafd90ae3ff14aaafd16feb50e3e47a193d3fe6f993f3c6e4f56ad55cb5b4681b7f0adceb0f9addb889d44d05c59551ddece70d08aa2a59fb53fd6349212588ca33712d968bb3a13d78d819be7f7d3e2ac990948ea48ad8bc2ba59bb76e1c491b0c3d7880c7f02084c90ba6dca35a75ea8a2845dd87a25cc88891cd4b983fd98216b }

condition:
	$a0
}

        