rule Win_Trojan_Hupigon_907
{
strings:
	$a0 = { 196a21c128a867c9725351591b8cd01ae595399d4afbe1178a172f600826eb2d552c944adaa109fab8fa36b06ebe09318db819e5c7e2a8954945388f7dfbe066d5c776d400a50fbfa8e1edd9cde75aeee86fd58722937decdc82c4c1d81e48 }

condition:
	$a0
}

        
