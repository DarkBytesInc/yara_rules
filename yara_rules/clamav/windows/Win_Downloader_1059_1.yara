rule Win_Downloader_1059_1
{
strings:
	$a0 = { 7e7dd1d098b62e08b4cfb014b1266a52bf7d0fa4e8e2011378a144f83c2377c9be1040f2ccc6cadbb6078a27cc210262411f15eda36d348ecc3fe9052062d2802f279164eb20b80a54f2feb8cce0acea1ce3208ec0db5500857f3ef1 }

condition:
	$a0
}

        
