rule Win_Downloader_Banload_1576
{
strings:
	$a0 = { 9abd0f5c5455fa3f7e67e602038e32282a2a26b56389ff02b10207720406f10f3af24f44d02c98d0480dee55db40861dd9b81cd9d8fdd86efbabfdac7eacddd6f5b31ffab345d6d6c0107fd22d4457512c49dd42afd5a4ac0c4aceef79ce3d33a099d6d797c3fbdcf3e739e73ce739cf79ce9f7b2eaf37719a80c44d9b }

condition:
	$a0
}

        
