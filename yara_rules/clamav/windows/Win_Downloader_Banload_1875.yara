rule Win_Downloader_Banload_1875
{
strings:
	$a0 = { 1e5741322c6842e80687ddcf5771135613aa88752d5a34229b506f1d9c2f4c37b8de38eac2af5f5bdbda066ff9ef806acc37952c1e2d24a77e6f906b4e485635e89172760d0adf9602b82d2e57eb007a2c283c417ea5941d4c441aafeac25bc4c2a43eab4fb6621e36d4e38773ca96e8de4699dbf414c9891f0325070e471a32794dd0b7c31ae6912991e7e68b64 }

condition:
	$a0
}

        