rule Win_Trojan_Startpage_88
{
strings:
	$a0 = { f6342f3f3d42e63777460efc434a3c4f47a14fdb2256d04c503b5448634c384bb35adb5200105360615e29feff1c282c22c227252f320f2e2d207265627466066c33766f7840075c797180849081756d5f077c7787858a337f8eb8658b9272847d8f0e97446a9e8194989c90d8897be899679f }

condition:
	$a0
}

        