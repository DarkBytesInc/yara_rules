rule Win_Downloader_1345_1
{
strings:
	$a0 = { 12fdc2faf1053faa980cfd4c0b47552345df0fe3458cdce0ca17dc11fdfc44d591adca0c08e186dc22c7fa260efd490afd55c296885f472e900dfd06fdf7e5b962e1eeab7c090c54b1d9917a35eba116aede76e5fd14d10bb9f706fdcd6088a78965d2f7783d }

condition:
	$a0
}

        
