rule Win_Downloader_Banload_1816
{
strings:
	$a0 = { a23dfff9a643fffdc55dffffd371ff926740ffb79b82fff0d7bfffffe8d0ffffe8d1ffffe7d1ffffe8d1ffffe8d0ffffe8d1ffffe8d1ffffe8d1ffffccb2ff996b68ff0000008f0000002f00000000c3a04e4ad0a65c5400000000c3943509e2b747f9f8c84bfff6c4 }

condition:
	$a0
}

        
