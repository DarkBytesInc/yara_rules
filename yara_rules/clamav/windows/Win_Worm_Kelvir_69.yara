rule Win_Worm_Kelvir_69
{
strings:
	$a0 = { 47d617040b483f4611735936c883b8d899873a063738ed7f17463a46f089b2cbb5785aefc9673338d4bbc50e79a362a360c6bc69f63ab654c93fa46f8c436adbb5b8e6131cc5f50bbaeea02a10abaf0d90eae35f511571a74a28ea9192f64bbe8bb70992da39e0149c7289cc337c62723fc0e0ebc62ac82ca76869 }

condition:
	$a0
}

        