rule Win_Downloader_93419_1
{
strings:
	$a0 = { 9055573e03c12bc133c003d652925a89342403d652925a8d74241803d652925a33c903d652925a5e3e3e8d400083ec043e3e8d400081c9686e6debe986000000e887000000e9820000006aff3e3e8d4000593e3e8d400081e1226c23d73e3e8d }

condition:
	$a0
}

        