rule Win_Trojan_Yspy_1
{
strings:
	$a0 = { 49196e7170cbc28ee0b600628452510d04d164a3e5f040d5eb098dae6f38250ab5d320f446fc80855c206b0b48b3fa062ff6af54a5a1707af7bb1bda6ccb3c6c63d83261e3ac2b9e093e5c0a17ad23ab296d3a5284257fdd11b3343fefe0e16dc976e3c7d339c1712eaddc3b4c4c8c592170a365db6bd27761a9da701e9f4ed8235089545306c2484604c689cf4b92bff53990 }

condition:
	$a0
}

        