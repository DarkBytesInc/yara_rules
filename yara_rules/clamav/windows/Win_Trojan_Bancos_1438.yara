rule Win_Trojan_Bancos_1438
{
strings:
	$a0 = { eac93a53dc87667601f9d17a8d1ee71412c5ca4d8c8b529fc3014ab4da52e4e424e3a01ddd5b1d5a0aabb4f4613a739c12ea5756df68e26d3eea70f1307110faf40189cb888e6b59b14b76f567b6399fd26fae8f606379bf310d884cdd }

condition:
	$a0
}

        
