rule Unix_Tool_13432_1
{
strings:
	$a0 = { 31ff31f631d2b9efbeadde31dbb31731c0b075cd8031ffbefaffffbf31d289c131dbb31531c0b075cd80b8faffffbfff30c3 }

condition:
	$a0
}

        
