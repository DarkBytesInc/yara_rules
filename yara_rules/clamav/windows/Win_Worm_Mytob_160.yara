rule Win_Worm_Mytob_160
{
strings:
	$a0 = { 8fb1579dfea65b6af9e28e3bf289991e0dc6d1d04df6b2014c00351134ec3a3b5d13a80955469d8db42302d0106b44446c24e8224f75069eb8f4002f381bfc3e70b4b28e6f139eefec8250e1b050d4497d04dff1e20d56eef213f36a04fcfe70be639cf4b113185d619a30056f9364b64326f2ee4259cf70de9076dee7b592a0a35df1d85c8fed236688d5169aa897c49eacbe5725d8 }

condition:
	$a0
}

        