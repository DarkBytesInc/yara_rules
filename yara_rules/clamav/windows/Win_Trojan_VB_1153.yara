rule Win_Trojan_VB_1153
{
strings:
	$a0 = { 4000000000000000f246544c0eed484f9c15db2497e8647500000000000001000000293a200000000000000000000000000000000000000000000000203d20440000000090000000000000000200000004000000a72f32b48cb6a94b802e6d621a0c62ee01000000a0000000b000000001000000203d204101202833383500003a2000000000000000000000000000000000000000000000277f7599fc293d4fa09d0f1874a1b2b92b5b3d472795dc4083b328423c58840f06000000982f40005642352136262a000000000000000000000000007e000000000000000000000000000a000904000000000000e42140002017400007f8300000ffffff080000000100000003000000e9000000441340009c124000dc11400078000000810000008f00000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000fe5ecb849d739e46870b7288c2796e6b00000000000000000000000000000000010000008001000000000000 }

condition:
	$a0
}

        