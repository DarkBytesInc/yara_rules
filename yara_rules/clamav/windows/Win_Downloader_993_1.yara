rule Win_Downloader_993_1
{
strings:
	$a0 = { 51721703421d4a1bd7b12c26eb9026c4fb93a8c19e919185dee7e726c259584608fcc56aa4c881f62338c03fed1cd3ddd31083a2bf98c2c3aab330424f05bcf9bcd48fe0031fb684c67bb27d151f12bee0cb4ab93e00e071b737f5bd }

condition:
	$a0
}

        
