rule Win_Worm_Mytob_102
{
strings:
	$a0 = { 4d03a490c5afebd536654cc450638737824e93b62ffab66f1f175b5172723f5f0c0ac5256a4ea6e39cd1c1c5dc4107e693941d1c882fb09d0cba61d0b43b63c1315d0a1d5392838c57c11fd2a43fdb9887a37ee79ff2c808d77756afa9e7396de533fb4e6fda04c99e987948e7d3cdd46c2efb37016ca349d3f0a12e624ab830e51c77e1721b0be7c0d291bd00ee7ecf }

condition:
	$a0
}

        