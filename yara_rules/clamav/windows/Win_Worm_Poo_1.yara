rule Win_Worm_Poo_1
{
strings:
	$a0 = { 706964206675636b65722e0000558bec33c9515151515151538bda8945f88b45f8e80beaffff33c05568ff51400064ff306489208b45f8e805eaffff50 }

condition:
	$a0
}

        