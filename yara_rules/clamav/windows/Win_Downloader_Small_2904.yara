rule Win_Downloader_Small_2904
{
strings:
	$a0 = { dd73a93fdc7968dd72a4df00362de73d75fc50e5d578615db2f0d265e9e2827931be15d33c0b7543befcdf790f273e3c089bdde05af03c63834e9c2df3a1dd5b58fb1c3b65c55b4a4ab9626a51e0040584ead05d68f60db1b0aaeee4cc3d599d810555b6c7fa6766ae714136bb416aacb2e0 }

condition:
	$a0
}

        
