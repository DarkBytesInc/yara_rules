rule Win_Downloader_Small_2724
{
strings:
	$a0 = { 1d4601eafac0737663686fea741c2e65789c200677696e04f5f654374473a9515f62436f56c7381c68747b9c3a2f47 }

condition:
	$a0
}

        
