rule Win_Downloader_26596_1
{
strings:
	$a0 = { 8bff558bec81ec78050000a11430000153568945fc578d8598faffff50c78598faffff14010000ff15cc10000133f683bd9cfaffff05752f39b5a0faffff7527c78594faffff0100000083bd9cfaffff0589b58cfaffff753083bda0faffff02752733ff }

condition:
	$a0
}

        
