rule Win_Trojan_Hupigon_713
{
strings:
	$a0 = { f83148026eecd98e0a45cfcbb37e601fdcd53c37ab1df14e6205acd68438400c817fd21a2c4c71f288533199f9af6a7e1b63d3dd3632da6bc0748902b032f856ff1079d2ef31a36bc6f3f9b1eaf0d4b4b44df1af3cb7e215 }

condition:
	$a0
}

        
