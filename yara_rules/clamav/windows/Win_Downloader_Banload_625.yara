rule Win_Downloader_Banload_625
{
strings:
	$a0 = { 43f12a9e101010d08c9f3e9192cce6550ac3edaf5934eabfd261551d936ab523c513a3d3ab28cf49b31494cabf8cfb0f4961829bde36d757adcaa9a068fa8d6cff984a9254bffdc0f6eebbd75ce994afe288d1f69720e48eeeab }

condition:
	$a0
}

        
