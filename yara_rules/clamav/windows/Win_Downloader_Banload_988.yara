rule Win_Downloader_Banload_988
{
strings:
	$a0 = { 4109124f889bad06ae07f5c6fe4f4eb788cc363121f23a3bac6e1769529c7e49ea09eb9fe481c229d995899ae8b32fac414c87cf68955f7b16fc9fb981e227dec8c3be9a99e695858d7f0775ce125f833cce74cceabd1e12fb43a0451a9bda22e3a15c9f537dcf2ebb3cd60eb97b }

condition:
	$a0
}

        
