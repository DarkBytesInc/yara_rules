rule Win_Downloader_1188_1
{
strings:
	$a0 = { 8d05bc81249de2e399cf18939b12a8123420e063d101d4ff7fedc0b1adc91613a214bbfa68849ed0fd1ff9fedea1db8718e937fe0139ed30db004f40439fffcefacbfe6a9b688c8e6c4ffce99972f78ed043703a59f830f6828e4404 }

condition:
	$a0
}

        
