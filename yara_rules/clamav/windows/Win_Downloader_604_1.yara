rule Win_Downloader_604_1
{
strings:
	$a0 = { 4083f8367e083de40000007d014040568d44247868ff0000005068a87600106802000080e82c0400008bf083c410b84a0000004083f83f7e083dee0000007d0140 }

condition:
	$a0
}

        