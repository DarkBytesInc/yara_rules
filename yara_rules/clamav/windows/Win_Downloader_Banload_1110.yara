rule Win_Downloader_Banload_1110
{
strings:
	$a0 = { 8d70b8daf5091d7174c2039564a992af97c830c7cb83c55fa6b3e7e8424c353976265e0582eefb042c802d8537d7ca0482a29203816d387d66d7ee60942aeeaf540e3f40dffd5ec2003ddcdee224f1181d44 }

condition:
	$a0
}

        
