rule Win_Proxy_Lager_29
{
strings:
	$a0 = { 0e2d69fed4ff24c1081d27b85143d38246190911838be7c8e96611d99411f758812e677580e70d5597cbf0fafe3340476df0a0f8a4af67d64611198570e02d9740d150cb0e00d7135b159092c64935ec8346777ea1990e009df8f7733868ccb95c1c216acbb62c8c8fc1fe825d2e63efa6235a818020330f799a157afabc8d87d9564568c6409be4babd8894bcf76db58b823f53dbca }

condition:
	$a0
}

        