rule Win_Spyware_Banker_3615
{
strings:
	$a0 = { b4ba04ca57702e6541626be6c411e3a8c23769f98410021038781489cedd951c6afbb9126f24bf66e3ad8e1c65af5861ed9b2c7ae71bc821bf69b475091bc5a2a5b3ba3d51bb6eb1426a019facacf79ee45797973ee6482ed08de77fe00c4052a8ecb2657c1d269e48b05a69baea6a3144b3bada592a61039997e8819ccb02bf1c96a7f003305b9c61690b2c }

condition:
	$a0
}

        