rule Win_Trojan_Mybot_6786
{
strings:
	$a0 = { 7eb70d609c64a7edfbffdd3f6d5c2c1ca626fa7d834cc78895db25b2f5572c3dc7153cb691652f434c631d534906f610abe5ed6983d3b9ecab3a3af9b8560e98c2a5af708a6de9ba98481106a5e1ccf4a97af4960cc3a5f8a9e2fb6c846e1d4b5b04be267bacaecdb42b9262987efcb6daa0cfe86a4e5a41ca0242c01a3146385af0563c59ab8767a37a04b58dbfc835a87fc23cc975 }

condition:
	$a0
}

        