rule Win_Trojan_Bancos_1952
{
strings:
	$a0 = { 95307cbdb0b5213c3d346b4929eea7be2eea5cdcd588e1b6025b2c0adbe541b1eb63534f5b56cabe8d0c3c491e5796a0b4ecb24f5e92ccd6508c49e0e7d5635ac21a05e750a4102c47c164fa66f60e3ee7ed8ccbe7810842a147 }

condition:
	$a0
}

        
