rule Win_Trojan_SdBot_4324
{
strings:
	$a0 = { 4187c15101bbe6267fd63bc9b8fac027c0a2fd4fca38adca2d5a8b4dfe16a0da1967d35934fd59a744e4008351ca4c368f5f0a39b66e38d685d46f3a8640b2625a079a3bce34fd711d4c64c68c3f247dfc6147926f72d57f1e6299fa39846bd5ab2a544ad6c8b53477ad85fc7f4bf32005599c733587ec9ad7788d31cca7bec9fad0ac88bddf68ec5b0b00c2b415e067027c05eb }

condition:
	$a0
}

        