rule Win_Trojan_VB_1335
{
strings:
	$a0 = { 51255342a17570b24932b36500000000000000000000000000000000000000001000000000000000000000000000000000000000000000009d00000000000000cc1a40004c00000006000000442b4000070000000c28400007000000c02740000700000074274000070000003c27400007000000e826400007000000a4264000070000004c26400007000000f825400007000000ac254000070000004825400007000000ec2440000700000090244000070000004424400007000000f423400056423521f01f56423644452e444c4c00000000002a000000000000000000000000000a00070400000904000000000000041d400000f0300000ffffff080000000100000001000000e9000000a41b40006c1b4000881a4000780000007f00000088000000890000000000000000000000000000000000000067686f7374790050726f6a656b743100006950726f746563746f725374756200f40100008021400000000000d030400090a64000140b000008b040004618400000b040002a005c00410043003a005c005500730065007200 }

condition:
	$a0
}

        