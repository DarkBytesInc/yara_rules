rule Win_Trojan_Vundo_265
{
strings:
	$a0 = { dedb419e33bb4c490782f44075aa657c45566cc919a42f373758db5e6c0c957e65284e1d3756c4eac59e134b891297be29e5662d8a7e457fce484771b28d953a1648adf148255030e97c072eaaedbc69e749b82f29bf4e20e34ce8495570dfd740e39c58270c075309c3eb96e5a174550facf09f30af075b0ac434dbdcd5e07a8abfa631bf74218aca7907e8 }

condition:
	$a0
}

        