rule Win_Spyware_4547_1
{
strings:
	$a0 = { f7d3f7d360534b5be80000000081c1ff7c000081e9ff7c00005ab804010000560f00ce5e03c256be378100005e50602b }

condition:
	$a0
}

        
