rule Win_Trojan_SdBot_2545
{
strings:
	$a0 = { 958147d03823468c6e9f496c01c34b8bb9b7f6dd61d54e049606c045dbf5d6c2603c1b831dcf51ef9acfcfb97851f8710ece1585616243c4ea6049877bf28a26815f5c2ea3594429b14e0eda0ff95f8b00a2682363cf5af901c373a7699d2a1d084c458f7be3e16e0a2ceb8955c7508d61f900f95668fb3d1ae8408d81435a2e6041b2a30093e1b1281e51b8 }

condition:
	$a0
}

        