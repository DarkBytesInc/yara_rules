rule Win_Downloader_Agent_32270
{
strings:
	$a0 = { c936cbc8c8b6215de5678335eb26235f5d3572098475107b5fd46db8c1778aba6d6324720245c718799d6c8641672caa7c72087b8faa1c1d252ed6deec013450aa24ec64fba0806cfe84041588c8f2c1271c648798590a818005100eb230c8f1a8090d843a1b7b9b8c28d9f176cd61660d85fb1071926512f1c00bab72ed0ab405966168596bd7c06e970b986cc0b8089476aa30 }

condition:
	$a0
}

        