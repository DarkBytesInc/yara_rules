rule Win_Trojan_SdBot_2814
{
strings:
	$a0 = { dc8f21aab2790949d8b2c23ed9de96ca6aac32a3b2781c2c1c51ae0aaf5b24ac24aa074d282ad6380c746f2829c82f836e7f17a9e5782c5d25b8352bfc9f9fa87428c3cfafd14d14989c7dff41448503aa9ff76b1b8832b8d8d136db4cf7ff85dd9c1b3953c1d20bbd8565211ef224bbf4f76519eaacc79a9638a88571a9b26c9ab7b22369445bd845690cad60ae3a5b161c0423ba35 }

condition:
	$a0
}

        