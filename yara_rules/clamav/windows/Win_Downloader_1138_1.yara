rule Win_Downloader_1138_1
{
strings:
	$a0 = { b5bc74d1dd495503d1027475dc50eb57142e6e0bf04b3248b12cb57a373060cd4e6dcb6d59a06128de444d0933808d6db34fc1e3005dcc53c5d68205580753ae2f4a06060db4cbbfcdb325bcd0efbedc2edbb00fcee92b47db4dd943 }

condition:
	$a0
}

        
