rule Win_Trojan_SdBot_168
{
strings:
	$a0 = { 5e816d5059677e3f4b54d94c9726ddd77002ee219c0328e14f6aa9d5d13242ea0a44ba867e1ad24048d9b1b58a65ead5c8dd04ff52d88c4162f586f3d9f0ecbe754b5a0a0ad7bbca6b3a68826779fc504483f543447953bf8ed6755e0e5753e884cc0cc37ec9fa0fd783579edd9eef6d3a01b65632dd95a79f4160ef5ce7edb18b17123e4a98021dd585d0b23463bebadb0ba6d175 }

condition:
	$a0
}

        