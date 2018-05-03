rule Win_Worm_Gaobot_18
{
strings:
	$a0 = { 614523db039b59fc2cdfcb35507a2c8e90de92db660e0009fd88765c21517c640a34af20b84d880d785946c8ebf947bba7d7fb5352628ae7bced63ee2ab8975da0afbf1aa94ea361b312617a612a41ae55c01ca40cb4d828f4ddc34dc17bdfc324bad0d80f6a61a8d41e76 }

condition:
	$a0
}

        
