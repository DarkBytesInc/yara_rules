rule Win_Trojan_Spambot_214
{
strings:
	$a0 = { 1742478425eeb54d08244af932affb6327ff17ffffb45d89a3d0273027800a052b3e0ab08fa151330a75da9d3fad49feffffffdb95e82faf7eabe456ed3c6941d18c1360d10a44d60cecdf307adeccceed0fffffff8ff14f5966390af7541f829385bd60b6ef2864cde655779895 }

condition:
	$a0
}

        
