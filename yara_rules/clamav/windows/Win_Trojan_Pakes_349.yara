rule Win_Trojan_Pakes_349
{
strings:
	$a0 = { 898c73d725d5bd03e204d3b70c69e13e09b092402d144d6f09888dbf861e13f100b7d4b2c0681b9c1c1514b48c167ba91548cd145ff116aefcd2a9b5dbc11554e81a90120c88203f3d1be5689b52c61942d8192816b2cda649e8d48a306751e0911b28c09be6566bfcb2c2c12f0cb1468943b1e7739f7b92c0041dff1d1d1c0c6bfbad4d5a8988b4639c49b0 }

condition:
	$a0
}

        