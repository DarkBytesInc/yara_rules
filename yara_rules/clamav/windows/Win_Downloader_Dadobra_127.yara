rule Win_Downloader_Dadobra_127
{
strings:
	$a0 = { 8e099e458b9c83f87aa6f9af41149e22ddf699466a515177197d17c3a8ab59dd03bbe837d18b8874c0c148ccd8bbac9ebae3fac22f5f3f9830712bb5199f2a1b4ea40ab1dea20c0b34b4d7f8c8f612732e3581005d3d9e5b3c1162b76d2b5ea23601e19c1c51 }

condition:
	$a0
}

        
