rule Win_Spyware_12215_1
{
strings:
	$a0 = { 3dcc6000106810700010ff75fcffd75985c059750ae8cc050000e9800100008d45dcc745dc67616d6550c745e0636c6965ff75fcc745e46e742e65c745e878650000ffd78b3d986000105985c059bb01001f0075218d45 }

condition:
	$a0
}

        