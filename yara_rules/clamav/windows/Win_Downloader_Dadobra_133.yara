rule Win_Downloader_Dadobra_133
{
strings:
	$a0 = { 5885dc55eeba280baea64db30eef993bf08d9f167025b00c949375a01c8d5fe61cdff7efd3beaf13731d5d591218c362bddb0c7abed1cbae908c80bdea526494f20944529494c59ca71d1a453a7ad4c55b7ddefd8f }

condition:
	$a0
}

        
