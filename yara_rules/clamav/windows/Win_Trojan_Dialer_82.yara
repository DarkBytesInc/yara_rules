rule Win_Trojan_Dialer_82
{
strings:
	$a0 = { 61726469616c657200004d61696e7065616e00000000200d0a200d0a4d61696e7065616e20476d62480d0a53636861726e77656265727374722e2036390d0a3132353837204265726c696e0d0a4765726d616e790d0a00000000696e666f40737461726469616c65722e646500004d69742064656d2025732077e4686c65 }

condition:
	$a0
}

        