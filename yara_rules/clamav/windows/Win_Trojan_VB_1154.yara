rule Win_Trojan_VB_1154
{
strings:
	$a0 = { 4000000000000000015d445963e3884385501bc07b2ca4d90000000000000100000000000000000000000000000000000000000000000000000000000000000000000000900000000000000002000000040000009d04e6f9f67bb14bac7712d109de228b01000000a0000000b000000001000000653d2a5c012044454144000045462d453337462d??????????????????????310035353369efb57585694d4ea7cf02ce096b049a1aa8b35e5ede3544a093a3064fbbbcfe060000001c3840005642352136262a000000000000000000000000007e000000000000000000000000000a000904000000000000f41340002417400007f8300000ffffff080000000100000003000000e900000018144000a8124000e811400078000000810000008a0000008b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000e829400000000000ffffffffffffffff000000003c2a40000090420003000000e81340001a00200000000000acb92e0480134000 }

condition:
	$a0
}

        