rule Win_Downloader_Banload_1652
{
strings:
	$a0 = { 14bf883788764fbc4a3716568e765410b0f913cef3b915b67eae7eedbf0ef54b670f43cf2fdcb1d11ed5f1f3517489431fe2e589a10e3171bd35523453a9c2399b3eb229dae388983639927ddfd3e6abcb4e96c5576b8d95f6451869e1836f4a458fd259e5730874a8fe795c3b271a02c191d43c6b9d8ac02c529a32648b258682bb812863c01adf4de2198d }

condition:
	$a0
}

        