rule Win_Trojan_Rbot_41
{
strings:
	$a0 = { f28489813dc234ff61d7c89a5879d894994bfd18fd18d85d0c12a9e165b378533107cbb2a76fe88ac98219d2a320ad11a9494ab5e3c42cb31f88ec8ce1797d20bb0eeed912cdc51f17611454cd22d5a6e7fb9e7cfe36dd066cc49a3f433ce77033e870ac60c83fabb1e4efbb6974e5eb0d2df80a78210f31 }

condition:
	$a0
}

        