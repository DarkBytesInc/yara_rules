rule Win_Trojan_Hupigon_275
{
strings:
	$a0 = { 9c933b80285d95dd4b1209f01c974c721be9274a2a93a87e4bef27b7022b15395061f1a827e09821696df31626f5b20da8c7708b6a48e7eff4df35bec96a7fc6ecdd6c5178aa6bfb03a3e8c063d52f94ff6c859cb1d453ed12a64eab1edadc1112491b6a7b50bd1d3c3518fb9bfe }

condition:
	$a0
}

        