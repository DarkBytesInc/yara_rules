rule Win_Trojan_Pakes_439
{
strings:
	$a0 = { 430fe114ff659c403c95c734c2f9b67dc3340780e7a84aecc31c0bfd601dc16ed64b013216fb789bf2a5bf3342a51827cfdcca53b571c32dd267f0323142c493de1f0452c21c747c971fb3e771d1d1569c6cc0a7d032cc25837c01cae6fb46df4ba26bff717583e8d247d7fee590e58543dae664a9231ad21697793cf71d784ba17fec8ab4190c34b9a0502f }

condition:
	$a0
}

        