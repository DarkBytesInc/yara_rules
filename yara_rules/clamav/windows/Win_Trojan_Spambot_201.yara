rule Win_Trojan_Spambot_201
{
strings:
	$a0 = { 138109ef9a135c3cab21f9ad0233cb99ffc80ecb524b7dff01feffa11c326c9877e41f951dfcd4af1a6745c0248479972429ffffffffd43df69a0502fd9ae25bd914cdee94698ee6d0759eeabf89bb630a3be8626a32ffffff5f6b79d0691686b3a59be498f57e7292f6736114f4 }

condition:
	$a0
}

        
