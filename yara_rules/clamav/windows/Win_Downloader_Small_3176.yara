rule Win_Downloader_Small_3176
{
strings:
	$a0 = { 50585181c2800d000081ea800d0000535b83ec0883c57c83ed7c0f014c24f8555d05ac0c00002dac0c000083c408595159525af3e2ca }

condition:
	$a0
}

        
