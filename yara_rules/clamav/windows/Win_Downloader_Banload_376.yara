rule Win_Downloader_Banload_376
{
strings:
	$a0 = { cf959c6d1b5f1d169b55b377bfc241fe347cc20d98ae39f3aa7eed07848e1e258d0af2e6fe3305195e87d16a895299064eb9495d0a2f28a4cdfb34f59c85dbe2b0259f8d349e227dc0076c574ab21c9e9e99385a7a6669bfd14b8a2df6863d32ffeed282 }

condition:
	$a0
}

        
