rule Win_Downloader_Small_626
{
strings:
	$a0 = { 696f6e5c52756e000000716277006266570062665200a01e4000b01e4000b01e4000e01040000011400010114000101140001011400020114000301140004011400010114000501140005011400060114000001040009010400090104000a0104000b0104000c01040001011400040114000101140001901000000000000c000000000000046 }

condition:
	$a0
}

        