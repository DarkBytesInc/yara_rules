rule Win_Trojan_Kates_69
{
strings:
	$a0 = { 01c0d1e8c38d4000c38d40009090c390558bec33c055683510400064ff30648920ff050070400033c05a5959648910683c104000c3e9ceffffffebf85dc38bc0832d0070400001c3558bec33c055686d10400064ff30648920ff050470400033c05a59596489106874104000c3e996ffffffebf85dc38bc0832d0470400001c3ff25449040008bc0ff25409040008bc0ff253c9040008bc0ff25509040008bc0ff254c9040008bc0558bec33c05568cd10400064ff30648920ff050870400033c05a595964891068d4104000c3e936ffffffebf85dc38bc0832d0870400001c39090729f9d511258001572e35ff9920818519f9ca4e92da21b356eb26475658b8475aa674c3198b5ee29007379256ae9a77c7e849a82357fccf9aee6e09a0151fcab546a5c94c84362164a2f14f9804a5fdadfd2fc5542bd8720110c58cae7ec73a9f1df8daf00b05625eb11f5344f9cd1ecddfa }

condition:
	$a0
}

        