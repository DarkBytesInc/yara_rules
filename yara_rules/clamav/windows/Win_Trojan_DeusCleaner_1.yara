rule Win_Trojan_DeusCleaner_1
{
strings:
	$a0 = { 55544e2d5553455246697273742d4f626a656374[0-90]42656c697a652043697479[0-12]353220436f726b20537472656574[0-12]4465757320436c65616e657220496e632e }

condition:
	$a0
}

        