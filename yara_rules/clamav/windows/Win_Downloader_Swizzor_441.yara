rule Win_Downloader_Swizzor_441
{
strings:
	$a0 = { a1b91592d561e02e0a999ea5aa42ad3e2c74f989eae4d22db714d231074934eabb99585b8843ed8f152fa09cca90f21f7a32446012fa2e8aeab6a17de4d2579391a83c2fe75137c36606330543a3746cbcd356fabb8eadbfa5b6 }

condition:
	$a0
}

        
