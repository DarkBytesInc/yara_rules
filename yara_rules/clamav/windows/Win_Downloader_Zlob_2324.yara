rule Win_Downloader_Zlob_2324
{
strings:
	$a0 = { 92ef25bd42f357945814204fb2e4b40c30da11c7de506c87af3d758c330a6708e9837905909e79b64d49fd2ae217a1088e8ceb12387699fbb22a1e702cde345298888df0eddfa196c42425c49621900204ea7deea5e6a30f987fe998fd1e06bafd401982 }

condition:
	$a0
}

        