rule Win_Trojan_Haxdoor_7
{
strings:
	$a0 = { fe0f53eb1150536974653a207ffc01f29d48eb7d7ce808fb4fc9f7134f75746c6f6f6b7e912c911c037938d138d9b8685f5ebc0cb8679a23f987be8d45bc506a0054482dcbf65bbc1fb85023c010bcf1d22f }

condition:
	$a0
}

        
