rule Win_Trojan_VB_1370
{
strings:
	$a0 = { ff2580104000ff258c104000ff2590104000ff253c104000ff2584104000ff2560104000ff2558104000ff2554104000ff2540104000ff2550104000ff2518104000ff2574104000ff25981040000000684c124000e8eeffffff000000000000300000005800000000000000a175f31b9476b341a3bb9bffcba3fb8700000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000643640005642352136262a000000000000000000000000007e000000000000000000000000000a000904000000000000b8144000341a400000f1300000ffffff080000000100000003000000e9000000f412400044124000e8114000780000007e000000840000008500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000006113d498fc41db45ae77ebd005f6bf4e0000000000000000000000000000000001000000 }

condition:
	$a0
}

        